# Security

Portcullis is meant to hold against containers that actively try to get past their rules, so a way around them is a security issue.

Please report it privately, through [GitHub's vulnerability reporting](https://github.com/nikarh/portcullis/security/advisories/new), not in a public issue. Include what the container needs (capabilities, labels, network settings) and how to reproduce it. The `bypass` scenario in [`e2e/`](e2e/README.md) shows how such attempts are tested.
