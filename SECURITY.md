# Security

## Reporting

Write to **security@doblier.io**. You get a first reply within 24 hours, from a person,
saying who is looking at it. We then keep you informed until the report is closed, and
we tell you before anything about it is published.

Report by e-mail only; do not open a public issue for a security problem. PGP is not
required. Write in English or in the language you prefer; we will manage.

There is no bug bounty. We do not promise a reward, and we do not pay for reports. We
credit reporters who want to be credited, in this file and in the fix's notes.

## What to report

Anything in this repository, or in the relay it talks to, that would let:

- a message reach someone who did not consent to receive it, or come from someone
  other than who it claims to be;
- a limit the relay enforces (messages a day, wake-ups, the end date, bounces, the
  recipient cap, pauses, blocks) be passed, from the bridge or from the network;
- message text, a key, a token, a pairing code, a phone number or an e-mail address
  reach a log, an error, a file on disk other than the key file, or another host;
- a signed record verify when it should not, or fail to verify when it should;
- the bridge talk to any host other than the relay, open a listening port, or run
  anything it received as a message;
- a pinned dependency be replaced by something else at install time.

When you report, describe the shape of the problem and how to reproduce it. Do not send
real message bodies, keys or other people's identifiers; a made-up example is enough.

## What not to do

Do not test against accounts, devices or relays that are not yours, and do not try to
read, hold or change other people's messages. Test against your own bridge and account,
or against a relay you run yourself.

## Scope and versions

In scope: the code in this repository (the bridge in `services/bridge` and the shared
package in `packages/common`) and the relay that the owners of this repository run for
the test. Out of scope: the assistants that run beside the bridge, and services the
relay does not operate.

The latest commit on the default branch is the supported version. Fixes land there
first; the private commit each public tree was built from is named in `README.md`.
