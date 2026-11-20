# MCP tool listing fixtures

Realistic, defanged MCP tool listings for tests and documentation.

- `safe/`: listings that must produce no HIGH or CRITICAL findings. Modelled on common real servers.
- `malicious/`: one defanged listing per MCP rule (SG-101 to SG-106) and one for tool poisoning. Each file has a comment or is described here with the rule it targets. These may be expected failures until the corresponding rule lands.

**Every sample is defanged.** URLs use `example.com`, keys are dummy values such as `sk-test-000000`, and nothing here runs or connects. See "Test samples must be safe" in CONTRIBUTING.md.

| File | Targets |
|------|---------|
| safe/filesystem-restricted.json | Restricted path filesystem server |
| safe/search-readonly.json | Read-only search server |
| safe/calculator.json | Simple calculator |
| malicious/sg-101-unsafe-auth.json | SG-101 Unsafe server authentication |
| malicious/sg-102-overbroad-permissions.json | SG-102 Over-broad tool permissions |
| malicious/sg-103-unrestricted-path.json | SG-103 Unrestricted path parameter |
| malicious/sg-104-suspicious-name.json | SG-104 Suspicious tool name |
| malicious/sg-105-missing-schema.json | SG-105 Tool with no description or input schema |
| malicious/sg-106-excessive-tools.json | SG-106 Excessive tool count |
| malicious/tool-poisoning.json | Tool poisoning (hidden instructions in description) |
