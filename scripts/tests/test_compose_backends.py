import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ComposeBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.project = Path(self.temp.name)
        for name in ("docker-compose.yml", ".env.template"):
            shutil.copyfile(ROOT / name, self.project / name)
        shutil.copytree(ROOT / "compose", self.project / "compose")
        self.environment = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("APP_", "MYSQL_", "POSTGRES_", "COMPOSE_"))
            and key not in ("FEATURES", "BIND_ADDR", "GRAFANA_ADMIN_PASSWORD")
        }

    def render(self, override=None, profiles=(), exported=None):
        command = ["docker", "compose", "-f", "docker-compose.yml"]
        if override:
            command += ["-f", f"compose/{override}.yml"]
        for profile in profiles:
            command += ["--profile", profile]
        command += ["config", "--format", "json"]
        result = subprocess.run(
            command,
            cwd=self.project,
            env={**self.environment, **(exported or {})},
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout)

    def test_plain_compose_does_not_forward_shell_database_settings(self):
        config = self.render(exported={
            "APP_DATABASE__URL": "postgres://host.invalid/database",
            "APP_DATABASE__HOST": "host.invalid",
            "APP_DATABASE__PASSWORD": "host-password",
        })
        self.assertEqual(set(config["services"]), {"app"})
        app = config["services"]["app"]
        self.assertEqual(app["build"]["args"]["FEATURES"], "memory")
        env = app["environment"]
        self.assertEqual(env["APP_SERVER__HOST"], "0.0.0.0")
        self.assertNotIn("APP_DATABASE__URL", env)
        self.assertNotIn("APP_DATABASE__HOST", env)
        self.assertNotIn("APP_DATABASE__PASSWORD", env)

    def test_partial_env_keeps_container_listener_reachable(self):
        (self.project / ".env").write_text("APP_ENV=production\n", encoding="utf-8")
        config = self.render()
        env = config["services"]["app"]["environment"]
        self.assertEqual(env["APP_SERVER__HOST"], "0.0.0.0")

    def test_template_copied_to_env_renders_all_profiles_without_warnings(self):
        shutil.copyfile(self.project / ".env.template", self.project / ".env")
        config = self.render(profiles=("*",))
        environment = config["services"]["app"]["environment"]
        self.assertEqual(environment["APP_DATABASE__HOST"], "db")
        self.assertEqual(environment["APP_DATABASE__PASSWORD"], "postgres")

    def test_postgres_override_matches_database_credentials_and_fixes_address(self):
        defaults = self.render("postgres", ("postgres",), {"FEATURES": "postgres"})
        default_app = defaults["services"]["app"]["environment"]
        self.assertEqual(default_app["APP_DATABASE__HOST"], "db")
        self.assertEqual(default_app["APP_DATABASE__PORT"], "5432")
        self.assertEqual(default_app["APP_DATABASE__USERNAME"], "postgres")
        self.assertEqual(default_app["APP_DATABASE__PASSWORD"], "postgres")
        self.assertEqual(default_app["APP_DATABASE__NAME"], "status-list")

        (self.project / ".env").write_text(
            "POSTGRES_USER=custom-user\n"
            "POSTGRES_PASSWORD=custom-password\n"
            "POSTGRES_DB=custom-db\n",
            encoding="utf-8",
        )
        config = self.render("postgres", ("postgres",), {
            "FEATURES": "postgres",
            "APP_DATABASE__HOST": "localhost",
        })
        app = config["services"]["app"]
        environment = app["environment"]
        self.assertEqual(app["build"]["args"]["FEATURES"], "postgres")
        self.assertEqual(environment["APP_DATABASE__HOST"], "db")
        self.assertEqual(environment["APP_DATABASE__PORT"], "5432")
        self.assertEqual(environment["APP_DATABASE__USERNAME"], "custom-user")
        self.assertEqual(environment["APP_DATABASE__PASSWORD"], "custom-password")
        self.assertEqual(environment["APP_DATABASE__NAME"], "custom-db")
        database = config["services"]["db"]["environment"]
        self.assertEqual(database["POSTGRES_USER"], environment["APP_DATABASE__USERNAME"])
        self.assertEqual(database["POSTGRES_PASSWORD"], environment["APP_DATABASE__PASSWORD"])
        self.assertEqual(database["POSTGRES_DB"], environment["APP_DATABASE__NAME"])

    def test_url_only_database_config_does_not_gain_split_fields(self):
        (self.project / ".env").write_text(
            "APP_DATABASE__BACKEND=sqlite\n"
            "APP_DATABASE__URL=sqlite::memory:?cache=shared\n",
            encoding="utf-8",
        )
        config = self.render()
        env = config["services"]["app"]["environment"]
        self.assertEqual(env["APP_DATABASE__BACKEND"], "sqlite")
        self.assertEqual(env["APP_DATABASE__URL"], "sqlite::memory:?cache=shared")
        for key in ("HOST", "PORT", "USERNAME", "PASSWORD", "NAME"):
            self.assertNotIn(f"APP_DATABASE__{key}", env)

    def test_mysql_uses_the_same_custom_credentials_for_app_and_service(self):
        (self.project / ".env").write_text(
            "MYSQL_USER=custom-user\nMYSQL_PASSWORD=custom-password\n"
            "MYSQL_DATABASE=custom-db\nAPP_DATABASE__HOST=old.invalid\n",
            encoding="utf-8",
        )
        config = self.render("mysql", ("mysql",), exported={
            "APP_DATABASE__URL": "postgres://host.invalid/db",
            "APP_DATABASE__PASSWORD": "host-password",
        })
        self.assertEqual(set(config["services"]), {"app", "mysql"})
        app = config["services"]["app"]
        self.assertEqual(app["build"]["args"]["FEATURES"], "mysql")
        env = app["environment"]
        database = config["services"]["mysql"]["environment"]
        for app_key, service_key, expected in (
            ("USERNAME", "MYSQL_USER", "custom-user"),
            ("PASSWORD", "MYSQL_PASSWORD", "custom-password"),
            ("NAME", "MYSQL_DATABASE", "custom-db"),
        ):
            self.assertEqual(env[f"APP_DATABASE__{app_key}"], expected)
            self.assertEqual(env[f"APP_DATABASE__{app_key}"], database[service_key])
        self.assertNotIn("APP_DATABASE__URL", env)
        self.assertEqual(env["APP_DATABASE__HOST"], "mysql")
        self.assertEqual(env["APP_DATABASE__PORT"], "3306")
        self.assertEqual(env["APP_DATABASE__BACKEND"], "mysql")

    def test_sqlite_has_a_persistent_writable_volume_and_clears_split_fields(self):
        config = self.render("sqlite", exported={
            "APP_DATABASE__HOST": "host.invalid",
            "APP_DATABASE__PASSWORD": "host-password",
        })
        self.assertEqual(set(config["services"]), {"app", "sqlite-data"})
        app = config["services"]["app"]
        self.assertEqual(app["build"]["args"]["FEATURES"], "sqlite")
        env = app["environment"]
        self.assertEqual(env["APP_DATABASE__BACKEND"], "sqlite")
        self.assertEqual(
            env["APP_DATABASE__URL"],
            "sqlite:///var/lib/status-list/status-list.db?mode=rwc",
        )
        for key in ("HOST", "USERNAME", "PASSWORD", "NAME"):
            self.assertEqual(env[f"APP_DATABASE__{key}"], "")
        volume = next(v for v in app["volumes"] if v["target"] == "/var/lib/status-list")
        self.assertEqual(volume["source"], "sqlitedata")
        self.assertFalse(volume.get("read_only", False))
        self.assertEqual(app["depends_on"]["sqlite-data"]["condition"], "service_completed_successfully")
        initializer = config["services"]["sqlite-data"]
        self.assertEqual(initializer["network_mode"], "none")
        self.assertIn("chown 65534:65534", initializer["command"][-1])

    def test_redis_override_selects_the_redis_cache(self):
        config = self.render("redis", ("postgres", "redis"), {"FEATURES": "postgres,redis"})
        self.assertEqual(set(config["services"]), {"app", "db", "redis"})
        self.assertEqual(config["services"]["app"]["environment"]["APP_CACHE__BACKEND"], "redis")


if __name__ == "__main__":
    unittest.main()
