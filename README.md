# dlms-security

`dlms-security` is the DLMS/COSEM application security layer.

It owns security contexts, key access interfaces, invocation counter policy,
AES-GCM based APDU protection, and authentication helpers needed by
`dlms-association`, `dlms-xdlms`, `dlms-client`, and `dlms-server`.

The layer must not own persistent key storage, transport security, COSEM object
storage, association state machines, or xDLMS service orchestration.

## Documentation

- [Requirements](docs/00_security_requirements.md)
- [API](docs/01_security_api.md)
- [Architecture](docs/02_security_architecture.md)
- [Test Plan](docs/03_security_test_plan.md)
- [Implementation Plan](docs/04_security_implementation_plan.md)
