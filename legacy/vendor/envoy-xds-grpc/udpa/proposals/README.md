# UDPA RFCs (uRFCs)

## Introduction

This directory contains the design proposals for substantial feature changes for
UDPA. The goal of this process is to:
- Provide a reference for the UDPA transport protocol and data model standards.
- Capture design history and tradeoffs as the UDPA APIs evolve.
- Provide increased visibility to the community on upcoming changes and the
  design considerations around them.
- Provide ability to reason about larger “sets” of changes that are too big to
  be covered either in an Issue or in a PR.
- Establish a consistent process for structured participation by the community
  on significant changes, especially those that impact multiple clients and servers.

We have modeled the uRFC process on [gRPC
RFCs](https://github.com/grpc/proposal).

## Process

1. Copy the template [URFC-TEMPLATE.md](URFC-TEMPLATE.md).
1. Rename it to `$CategoryName$uRfcId-$Summary.md`, e.g. `TP1-xds-transport-next.md`
   (see category definitions below). The `$uRfcId` should be strictly higher
   than any existing or under-review uRFC in `$CategoryName`.
1. Write up the RFC.
1. Submit a Pull Request. The CNCF UDPA working group should be tagged with
   `@cncf/udpa-wg` and an e-mail sent to `udpa-wg@lists.cncf.io` linking to the
   PR. All discussion is expected to take place within the PR.
1. An APPROVER will be assigned by one of this repository's maintainers.
1. For at least a period of 10 business days (the minimum comment period),
it is expected that the OWNER will respond to the comments and make updates
to the RFC as new commits to the PR. Through the process, the discussion
should take place within the PR to avoid splintering conversations. The OWNER is
encouraged to solicit as much feedback on the proposal as possible during this
period.
1. If there is consensus as deemed by the APPROVER during the comment period,
the APPROVER will merge the proposal pull request.

## Proposal Categories

The proposals shall be numbered in increasing order.

- ``#TPn`` - Transport protocol.
- ``#DMn`` - Data model.
- ``#Pnn`` - Affects processes, such as the proposal process itself.

## Proposal Status
1. Every uncommitted proposal is effectively in draft status.
1. Once committed, a proposal is in finalized status.
1. If issues are discovered during implementation, revisions may be made by
   following the review process.
1. Once implemented by an xDS/UDPA client, this should be reflected in the
   `Implemented in:` header field of the proposal. Listing versions is not
   required.
