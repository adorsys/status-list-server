variable "RELEASE_BUILD" {
  default = false
}

variable "BUILD_VARIANT" {
  default = "smoke"
}

variable "FEATURES" {
  default = null
}

variable "DOCKER_METADATA_OUTPUT_JSON" {
  default = "{\"tags\":[],\"labels\":{}}"
}

target "default" {
  matrix     = { variant = [BUILD_VARIANT] }
  name       = variant
  context    = "."
  dockerfile = "Dockerfile"
  args       = { FEATURES = FEATURES }
  tags       = jsondecode(DOCKER_METADATA_OUTPUT_JSON).tags
  labels     = jsondecode(DOCKER_METADATA_OUTPUT_JSON).labels
  platforms  = RELEASE_BUILD ? ["linux/amd64", "linux/arm64"] : []
  output     = RELEASE_BUILD ? ["type=registry"] : []

  # Keep release provenance explicit regardless of repository visibility.
  attest = RELEASE_BUILD ? ["type=provenance,mode=max", "type=sbom"] : []
  annotations = RELEASE_BUILD ? [
    "index,manifest:org.opencontainers.image.description=${jsondecode(DOCKER_METADATA_OUTPUT_JSON).labels["org.opencontainers.image.description"]}"
  ] : []
}
