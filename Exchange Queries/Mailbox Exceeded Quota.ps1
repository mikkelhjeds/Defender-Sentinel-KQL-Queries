//
// Mikkel Hjeds
//
let usermailbox = "";
//Days (int)
// let startdays = ago(30d);
// let enddays = now();
//Dates datetime(yyyy-mm-dd)
let startdate = datetime(2023-02-28 00:00:00);
let enddate = datetime(2023-02-28 23:59:00);
//
EmailEvents
| where Timestamp between (startdate .. enddate)
| where SenderMailFromAddress == usermailbox
//
// | where Subject contains "Undeliverable"
// | summarize count() by Subject
