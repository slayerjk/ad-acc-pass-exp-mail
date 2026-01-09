<h1>Go: notify user(s) on password expiration by email</h1>

<h2>Description</h2>

Due to LDAP/AD has no attribute for 'password expires' you have to get ldap attr 'pwdLastSet' and calculate(+) max password age in you org to get expiration date.

If your AD password will be expired in 60d(check -pet flag) and you want to get notification about it 5d before this(check -pnt flag) - you will be notified by email.

If your pass is already expired - you will get notification also.

App is suppose to use your internal SMTP server without authentication(email addresses to notify must be the same domain as your SMTP server).

It uses following LDAP attributes:
* sAMAccountName - account name
* pwdLastSet - specifies the date and time that the password for this account was last changed(100-nanosecond steps since 12:00 AM, January 1, 1601, UTC)
* userAccountControl - 512=Normal; 8388608=Password Expired; OTHER=...check code

<h2>Flags</h2>

```
    logsDir := flag.String("log-dir", logsPathDefault, "set custom log dir")
	logsToKeep := flag.Int("keep-logs", 7, "set number of logs to keep after rotation")
	passExpThreshold := flag.Int("pet", 60, "password expiration threshold(after this threshold password will be expired), days")
	passNotifyThreshold := flag.Int("pnt", 5, "days before expiration for notification, days")
	mailHost := flag.String("mhost", "NONE", "REQUIRED, SMTP host, name or IP")
	mailPort := flag.Int("mport", 25, "SMTP host's port")
	mailFrom := flag.String("mfrom", "NONE", "REQUIRED, mail from address")
	mailTo := flag.String("mto", "NONE", "REQUIRED, mail to, email addresses separated by coma")
	mailToAdmins := flag.String("mtoa", "NONE", "mail to admins if errors occured(send log), email addresses separated by coma")
	mailSubject := flag.String("msubj", "Accounts with expired password", "mail subject for expired passwords")
	ldapFqdn := flag.String("lfqdn", "NONE", "REQUIRED, FQDN of your LDAP(AD)")
	baseDn := flag.String("basedn", "NONE", "REQUIRED, accounts' baseDN(OU) to search in AD, ex.:'OU=service accounts,OU=busines,DC=example,DC=com'")
	bindUser := flag.String("bu", "NONE", "REQUIRED, bind user, 'USER@DOMAIN'")
	bindUserPassword := flag.String("bup", "NONE", "REQUIRED, bind user password")
	timeZone := flag.String("tz", "Asia/Almaty", "your timezone from time zone db, ex:'Asia/Almaty', must be correct")
```

<h2>Workflow</h2>

- check all required flags are set
- make LDAP bind
- get accounts from baseDN OU
- enrich 'userAccountControl' description(512-ok, 8388608-pass expired, 514|546-disabled)
- convert 'pwdLastSet' from '100-nanosecond steps since 12:00 AM, January 1, 1601, UTC' to normal time.Time
- add timezone to 'pwdLastSet'
- calculate wether account's pass is expired/start notification before N days(-pnt flag) before expiration
- send mail to admins(-mto flag)
- send report to admins(-mtoa flag) if any error occured or there is/are any failures while processing accounts