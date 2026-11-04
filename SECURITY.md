# Security policy

The Bifrost agent runs on your servers with sudo rights for the operations it supports, so we treat flaws in it as serious.

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository. Please don't open a public issue, pull request or discussion.

Include what you found, how to reproduce it, the version (`bifrost-agent version`) and the impact you expect. We aim to reply within three business days and to agree a disclosure date with you once a fix is ready.

## Supported versions

Only the latest release gets security fixes while the agent is at 0.x. Upgrade by re-running `install.sh`; it keeps the agent's enrollment.

## Scope

In scope: this agent, `deploy/install.sh`, the release artifacts and their signatures, and the operations catalog. Especially anything that lets a hub, or anyone else, run a change without a valid passkey approval, escape the operation allow-list or sudoers rules, or install a binary that fails the signature check.

Report flaws in the Bifrost hub or the approver app here too.
