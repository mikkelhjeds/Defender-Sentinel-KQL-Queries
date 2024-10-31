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
// Returns devices with vulnerable software with CVSS score above x
DeviceTvmSoftwareVulnerabilities
| join kind=inner DeviceTvmSoftwareVulnerabilitiesKB on CveId
| where CvssScore >= 8.5
| distinct DeviceId, CveId
| summarize count()
```

<H2>Compare values with external threat intelligence feeds</H2>

```kql
// External list with distinct SHA values from abuse.ch malwarebazaar
let SHAList = (externaldata(SHAValue:string)
[@"https://raw.githubusercontent.com/test.txt"]
with(format="csv")
| distinct SHAValue);
// Compare devices for distinct SHA values
DeviceFileEvents
| where SHA256 in (SHAList)
```

```kql
// External List
let iplist = (externaldata(urlstring: string) [@'https://raw.githubusercontent.com/jreegun/Researches/master/Malware%20researches/Qakbot/Qakbot_OneNote_Campaign_Payload_Delivery.txt']);
// Filter list
UrlClickEvents
| where Timestamp > ago(30d)
| where Url in (iplist)
``` 
