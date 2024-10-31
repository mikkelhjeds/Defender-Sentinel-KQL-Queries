<H1>Defender and Sentinel Queries</H1>

<H2>Defender KQL Queries</H2>


<H3>Phishing related queries</H3>

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

<H2>Sentinel KQL Queries</H2>
