# Reporting a vulnerability

Please report security problems privately, through GitHub's private vulnerability reporting: the **Security** tab
of this repository, then **Report a vulnerability**. Do not open a public issue.

We are most interested in anything that lets a question run on a sensor without a valid member signature and the
service's countersignature, lets a question escape its unit's sandbox or read a secret file's bytes, or lets an
answer be read by anyone but the service that asked. `docs/security.md` describes what is meant to hold.

We will acknowledge a report within a few days and keep you informed until it is fixed.
