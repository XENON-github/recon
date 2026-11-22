## What and why

## Checklist
- [ ] Tests added/updated, and I saw the new test **fail** without my change
- [ ] `ctest` passes; sanitizer builds (ASan+UBSan, TSan) pass locally
- [ ] Parsers: bounds-checked, inputs treated as hostile, fuzz target updated if a matcher was added
- [ ] `docs/MANUAL.md` and `man/recon.1` updated for any new/changed option (`tests/doc_test.py` passes)
- [ ] `CHANGELOG.md` updated
- [ ] No new dependency, no exploitation/credential-guessing functionality
