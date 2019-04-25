# Flask Azure AD OAuth Provider - Change log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

* Add exception for `urllib3` dependency https://app.snyk.io/vuln/SNYK-PYTHON-URLLIB3-174323 
* Pinning `urllib3` dependency to later version to mitigate https://app.snyk.io/vuln/SNYK-PYTHON-URLLIB3-174464

## [0.2.0] - 2019-03-07

### Added

* Refactoring internal TestJwk and TestJwt classes to make some parts part of the main package

## [0.1.0] - 2019-03-05

### Added

* Initial version based on middleware developed for the BAS People (Sensitive) API
