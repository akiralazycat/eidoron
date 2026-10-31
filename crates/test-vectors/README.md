# P2.1 synthetic-only shape fixtures

No known-answer vectors have been generated or checked. The fixture helpers in `src/lib.rs` create **untrusted, invalid-ciphertext shapes** so the public v0 parser can be tested without cryptographic code.

They MUST NEVER be accepted as authenticated files, a valid encrypted archive or as sample real-user passwords. Next P2.2 creates independently checked, exact-byte vectors from the P1.4 plan, and only then should actual cryptographic code be evaluated.
