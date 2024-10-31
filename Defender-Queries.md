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
let SHAList = (externaldata(SHAValue:string) [@"https://raw.githubusercontent.com/...shalist.txt"]with(format="csv")
| distinct SHAValue);
// Compare devices for distinct SHA values
DeviceFileEvents
| where SHA256 in (SHAList)
```

```kql
// External List
let iplist = (externaldata(urlstring:string) [@'https://raw.githubusercontent.com/...urllist.txt']with(format="csv")
| distinct urlstring);;
// Filter list
UrlClickEvents
| where Timestamp > ago(30d)
| where Url in (iplist)
``` 


<H2>Network</H2>

```kql
// Check DeviceNetworkEvents for events that suggests open ports
// 21: FTP
// 22: SSH/SFTP
// 25: SMTP
// 53: DNS
// 80: HTTP
// 110: POP3
// 443: HTTPS
// 1433: MSSQL
// 1434: MSSQL
// 3306: MySQL
// 8080: Alternative HTTP
let portlist = dynamic([21, 22, 25, 53, 80, 110, 443, 1433, 1434, 3306, 8080]); //Add relevant ports in the list if needed
DeviceNetworkEvents
| where ActionType == "ListeningConnectionCreated"
| where LocalPort in (portlist)
| summarize OpenPorts = make_set(LocalPort) by DeviceName
| sort by array_length(OpenPorts)
```
