## Plan

### 1. Modify Status Enum
- Update `src/models.rs` to change `Status::APPLICATIONSPECIFIC` to `Status::ApplicationSpecific(u32)` to carry the actual integer value
- Add validation to ensure values are ≥ 256

### 2. Update Encoding/Decoding Logic
- Modify `src/utils/lst_gen.rs`:
  - Update `determine_bits` to extract actual value from `ApplicationSpecific` variant
  - Update `apply_updates` to validate values ≥ 256 and handle payload
  - Ensure proper encoding/decoding of status values

### 3. Add Unit Tests
- Add tests for:
  - Values < 256 being rejected
  - Values ≥ 256 being accepted
  - Proper serialization/deserialization

### 4. Verify CI Passes
- Run `cargo test` to ensure all tests pass
- Run full CI suite before committing