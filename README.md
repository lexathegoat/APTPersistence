## Supported Detection Techniques

### Windows
- Registry Run Keys(T1547.001)
- Windows Services(T1543.003)
- Scheduled Tasks(T1053.005)
- WMI Event Subscriptions(1546.003)

### Linux
- Cron Jobs(T1053.003)
- Systemd Services(T1543.002)
- RC.local Scripts(T1037.004)
- Shell Profile Modifications(T1546.004)
- LD_PRELOAD Hİjacking(T1574.006)

## Detection Report Structure

```json 
{
  "timestamp": "2025-10-31T10:30:00",
  "technique": "Registry Run Key",
  "severity": "HIGH|MEDIUM|CRITICAL",
  "location": "Path or registry key",
  "details": "Detailed findings",
  "os": "Windows|Linux"
}
```
## Severity Levels
- CRITICAL = Immediate threat requiring urgent response
- HIGH = Suspicious activity with high confidence
- MEDIUM = Potentially suspicious requiring investigation

## EDR Testing

The framework includes pre-configured test scenarios for
validating EDR capabilities. Each scenario contains:

- Test command for creating persistence
- Cleanup command for safe removal
- Expected EDR detection behaivor
- MITRE ATT&CK technique mapping

**Warning**: Only execute test scenarios in authorized testing environments.

## Legal Notice

THIS TOOL IS INTENDED FOR AUTHORIZED SECURITY TESTING AND DEFENSIVE OPERATIONS ONLY.
UNAUTHORIZED USE AGAINST SYSTEMS YOU DO NOT OWN OR HAVE EXPLICIT PERMISSION TO TEST IS ILLEGAL!

## License

**MIT LICENSE**

## References
- MITRE ATT&CK Framework: https://attack.mitre.org/
- YARA Documentation: https://yara.readthedocs.io/
- Sigma Rules: https://github.com/SigmaHQ/sigma
