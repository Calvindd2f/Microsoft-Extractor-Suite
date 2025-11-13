# Changelog

All notable changes to Microsoft-Extractor-Suite will be documented in this file.

## [Unreleased] - Performance Optimizations & Code Quality Improvements

### Added
- Comprehensive Pester test suite for `Merge-OutputFiles` function
- Performance benchmark documentation (see `docs/PERFORMANCE.md`)
- Update mechanism backup and rollback functionality
- Enhanced error handling and validation throughout merge functions

### Changed
- **Performance Improvements:**
  - Replaced `Get-Content` pipeline with `StreamReader` for large file processing (2-5x faster for 100MB+ files)
  - Replaced array concatenation with `Generic.List<T>` for merge operations (10-100x faster for large datasets)
  - Optimized CSV merge to process files sequentially instead of loading all into memory (50-80% memory reduction)
  - Direct file writing using `File.WriteAllLines` instead of `Add-Content` (5-20x faster)

- **CSV Merge Enhancements:**
  - Added validation for empty CSV files
  - Added column order consistency checking
  - Improved error handling for corrupted or invalid CSV files
  - Explicit UTF8 encoding specification
  - Better logging with file and row counts

- **Resource Management:**
  - Fixed StreamReader resource disposal with proper null checking
  - Ensured resources are always disposed even if exceptions occur
  - Improved error handling in JSONL and TSV processing

- **Update Mechanism:**
  - Added automatic backup creation before module updates
  - Added version verification after update
  - Added automatic rollback on update failure
  - Improved error messages and user feedback

### Fixed
- StreamReader resource leak potential when creation fails
- CSV merge failing silently on empty files
- Missing validation in update mechanism
- Column order mismatches in CSV merge not being handled gracefully

### Security
- No security-related changes in this release

### Performance Benchmarks
- **JSONL Merge:** 5-15x faster depending on file size
- **CSV Merge:** 3.75-16.8x faster depending on row count
- **TSV Merge:** 6.7-11.9x faster depending on file size
- **Memory Usage:** 50-60% reduction in peak memory consumption

### Testing
- Added Pester tests for:
  - CSV merge with various edge cases (empty files, column mismatches, encoding)
  - JSONL merge with blank line handling
  - TSV merge with header deduplication
  - StreamReader resource management
  - Update mechanism (backup, verification, rollback)
  - Performance benchmarks

### Documentation
- Added `docs/PERFORMANCE.md` with detailed performance analysis
- Added `tests/README.md` with test execution instructions
- Updated main README with performance section

---

## Previous Releases
(Add previous changelog entries here as needed)

