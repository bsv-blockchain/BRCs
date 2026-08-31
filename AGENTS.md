# BRC Repository Agent Instructions

These instructions apply to the entire repository.

## Numbering New Proposals

- Every new BRC proposal MUST use the lowest available positive BRC number,
  even when higher-numbered BRCs already exist.
- Before assigning a number, synchronize with the current `master` branch and
  inspect numbered BRC files and index entries, withdrawn or deprecated BRCs,
  historically assigned numbers, and numbers claimed by open pull requests.
- A withdrawn, deprecated, or historically assigned number remains unavailable.
- Select the lowest positive integer not assigned, reserved, or claimed by any
  of those sources. Do not select a convenient higher number or use a lettered
  placeholder when the lowest available number can be determined.
- Recheck availability immediately before pushing and immediately before
  merging. If another proposal has claimed the number, renumber the new
  proposal to the next-lowest available number and update all references.
- Use a four-digit, zero-padded filename in the appropriate category, and
  update the root `README.md`, the category `README.md`, and `SUMMARY.md`.
- Amendments to existing BRCs retain their existing numbers; do not renumber
  an established standard.
