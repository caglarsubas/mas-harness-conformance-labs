# Contributing

Every change is governed by one hash-pinned task packet and one pull request. Run only that packet's exact acceptance commands through the trusted offline launcher. Do not access a warm-source checkout, add a network fallback, or infer a live or tenant-acceptance state from offline evidence.

New campaign packets add only packet-authorized definitions, fixtures, tests, and descriptors. They do not edit the bootstrap Makefile or dispatcher.
