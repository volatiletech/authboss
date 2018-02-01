# Changelog

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2018-01-??
### Added
### Changed
### Deprecated
### Removed
### Fixed
### Security

## 2015-08-02
### Changed
This change is potentially breaking, it did break the sample since the supporting struct was wrong for the data we were using.

**Lock:** The documentation was updated to reflect that the struct value for AttemptNumber is indeed an int64.
**Unbind:** Previously it would scrape the struct for the supported types (string, int, bool, time.Time, sql.Scanner/driver.Valuer)
and make them into a map. Now the field list will contain all types found in the struct.
**Bind:** Before this would only set the supported types (described above), now it attempts to set all values. It does check to ensure
the type in the attribute map matches what's in the struct before assignment.

## 2015-04-01 Refactor for Multi-tenancy
### Changed
This breaking change allows multiple sites running off the same code base to each use different configurations of Authboss. To migrate
your code simply use authboss.New() to get an instance of Authboss and all the old things that used to be in the authboss package are
now there. See [this commit to the sample](https://github.com/volatiletech/authboss-sample/commit/eea55fc3b03855d4e9fb63577d72ce8ff0cd4079)
to see precisely how to make these changes.
