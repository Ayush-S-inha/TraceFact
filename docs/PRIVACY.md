# TraceFact Privacy Model

TraceFact is built to work locally.

## Defaults

* no telemetry
* no analytics
* no crash reporting
* no cloud analysis
* no account
* no API key
* no automatic phone home
* no raw payload capture by default
* sensitive values are filtered or rejected during collection

## Collection

TraceFact should prefer metadata over content. It should collect only the information needed to describe application behavior and discard events that are not useful.

Storage must stay within a user selected limit.

## Scope

The default target is a process or application chosen by the user. TraceFact should not start by watching the whole host.

## Sensitive data

Things such as authorization headers, cookies, API keys, passwords, tokens, and raw request bodies should not be stored by default.

Privacy is part of the collector design. It is not something added after the data has already been collected.
