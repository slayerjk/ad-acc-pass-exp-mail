<h1>Go: notify user(s) on password expiration by email</h1>

<h2>Description</h2>

Due to LDAP has no attribute for 'password expires' you have to get ldap attr 'pwdLastSet' and calculate(+) max password age in you org. to get expiration date.

If your AD password will be expired in 60d(check -pet flag) and you want to get notification about it 5d before this(check -pnt flag) - you will be notified by email.

If your pass is already expired - you will get notification also.

App is suppose to use your internal SMTP server without authentication(email addresses to notify must be the same domain as your SMTP server).

It uses following LDAP attributes:
* sAMAccountName - account name
* pwdLastSet - specifies the date and time that the password for this account was last changed(100-nanosecond steps since 12:00 AM, January 1, 1601, UTC)
* userAccountControl - 512=Normal; 8388608=Password Expired; OTHER=...check code
