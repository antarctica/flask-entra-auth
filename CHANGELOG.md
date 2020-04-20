# Flask Azure AD OAuth Provider - Change log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

* Bandit configuration file
* Sharing PyCharm test configuration through version control
* Adding GitLab release management
* Support for scopes from both `scp` and `roles` claims

### Fixed

* Signature of `FlaskAzureOauth.initapp(app=app)` changed to `.initapp(app)`, no longer requiring named parameter

### Changed

* Incorporating @maxgubler's contribution for Authlib 0.12
* Updating to Authlib 0.14.1
* Updating to Flask 1.1.2
* Updating to Requests 2.23.0
* Updating development dependencies
* Update project dates
* Switching to Poetry for dependency management and package publishing
* Switching to Black for code formatting/linting
* Switching to multi-stage Docker image
* Tidying up README
* Tidying up GitLab CI

### Removed

* Synk support - too unreliable

## [0.3.0] - 2019-04-25

### Added

* Upgraded to AuthLib 0.11

### Changed

* Add exception for `urllib3` dependency https://app.snyk.io/vuln/SNYK-PYTHON-URLLIB3-174323 
* Pinning `urllib3` dependency to later version to mitigate https://app.snyk.io/vuln/SNYK-PYTHON-URLLIB3-174464
* Simplifying Docker image name
* Simplifying release procedures

## [0.2.0] - 2019-03-07

### Added

* Refactoring internal TestJwk and TestJwt classes to make some parts part of the main package

## [0.1.0] - 2019-03-05

### Added

* Initial version based on middleware developed for the BAS People (Sensitive) API
