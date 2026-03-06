# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-06

First release of the dnsttEx fork. Changes since upstream (after ae95dda):

### Added
- Integration tests for concurrent connections and session management

### Changed
- Module renamed to dnsttEx
- DNS payload encoding: switched from Base32 to Base36
- DNS payload framing made more compact
- KCP: use modified implementation with 12-byte header
- Increased queue sizes; KCP misconfiguration adjusted
- smux keepalive and Poller backoff fixes

### Fixed
- Deadlock bug
- smux keepalive behavior
- Poller backoff behavior

[Unreleased]: https://github.com/AliRezaBeigy/dnsttEx/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AliRezaBeigy/dnsttEx/releases/tag/v1.0.0
