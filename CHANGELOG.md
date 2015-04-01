Changelog
=========

## 2015-04-01 Refactor for Multi-tenancy
This breaking change allows multiple sites running off the same code base to each use different configurations of Authboss. To migrate
your code simply use authboss.New() to get an instance of Authboss and all the old things that used to be in the authboss package are
now there. See [this commit to the sample](https://github.com/go-authboss/authboss-sample/commit/eea55fc3b03855d4e9fb63577d72ce8ff0cd4079)
to see precisely how to make these changes.
