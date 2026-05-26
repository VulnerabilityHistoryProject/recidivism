# Test Data Notes

If we configure recidivism.ini to point to our test data, we'll get this:


* GHSA-4j5m-wc25-pvh7
  * OneNote Path Traversal
  * Ecosystem: crates.io
  * Package: onenote_parser
  * Clone the repo: https://github.com/msiemens/onenote.rs/
  * Fix commit: c9267b2c96e2542be7e7b557d67318e81b733585
    * Date: Fri Jan 9 22:29:30 2026 +0100
    * modules: 
        * src/onenote/mod.rs
        * Cargo.toml
  * No origin commit
  * No other vulnerability has occurred for this package - therefore no recidivism

* DEBIAN-CVE-2026-43502
  * Linux kernel vuln
  * Ecosystem: DEBIAN
  * OSV published: 2026-05-21T13:16:19.520Z
  * We don't know its type, its fix, its origin. Really, we don't know its repo.
  * Recidivism should be empty

  
  * GHSA-f396-4rp4-7v2j
    * PyPI: boxlite
    * Path Traversal
    * CWE-22 is mentioned
    * Fix is available, but no git commmit is mentioned. 
    * Affected versions refer to the PyPI releases, so one could look up the release dates of the earliest affected version
    * No git commit mentioned, although pull requests are referenced

* GHSA-g6ww-w5j2-r7x3
    * PyPI: boxlite
    * BoxLite: Permission Bypass Allows Modification of Read-Only Files
    * NOT type recidivistic
    * CWE-284


