# Contributing to Authorino

## Open issues

Start by checking the list of [issues](https://github.com/kuadrant/authorino/issues) in GitHub. Maybe your idea was discussed in the past or is part of an ongoing conversation.

In case it is a new idea for enhancement, a bug fix, a question or whatever unprecedented contribution you want to share, before sending a pull-request, please make sure to [describe the issue](https://github.com/kuadrant/authorino/issues/new) so we can have a conversation together and help you fin dthe best way to get your contribution merged.

## Local setup

Make sure you have installed:
- [Docker](https://docker.com)
- [Golang](https://golang.org)
- [Operator SDK](https://sdk.operatorframework.io/)

Then fork the repo and download the Golang dependencies:

```sh
git clone git@github.com:kuadrant/authorino.git && cd authorino
make vendor
```

## Start contributing

- Make your local changes
- [Sign](https://docs.github.com/en/github/authenticating-to-github/signing-commits) your commits
- Send your pull-request

## Additional resources to contributors

- [Terminology](terminology.md)
- [Examples](../examples/)
- [Deployment instructions](deploy.md)
- [Code of Conduct](code_of_conduct.md)

## Logging messages

A few guidelines for adding logging messages in your code:
1. Make sure you understand Authorino's [Logging](logging.md) architecture and policy regarding log levels, log modes, tracing IDs, etc.
2. Respect controller-runtime's [Logging Guidelines](https://github.com/kubernetes-sigs/controller-runtime/blob/master/TMP-LOGGING.md).
3. Do not add sensitive data to your `info` log messages; instead, redact all sensitive data in your log messages or use `debug` log level by mutating the logger with `V(1)` before outputting the message.
