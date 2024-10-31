<H1>Defender KQL Queries</H1>


<H2>Phishing related queries</H2>

```kql
// Returns the logins from the users recieving emails from a specific sender
let sussender = "";
let emailUsersArray = toscalar(
    EmailEvents
    | where SenderFromAddress contains sussender
    | summarize UsersArray = make_list(RecipientEmailAddress)
);
AADSignInEventsBeta
| where Timestamp >= ago(7d)
| where AccountUpn in (emailUsersArray)
| where Country != "DK"
| where ErrorCode == "0"
| summarize count() by AccountUpn, Country
```

<H2>Vulnerable devices</H2>

```kql
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where CvssScore >= 8.5
| distinct DeviceId, CveId
| summarize count()
```
