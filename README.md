# GoAWSConsoleSpray

GoAWSConsoleSpray is a tool that can be used to spray AWS IAM Console Credentials in order to identify a valid login for a user account. The AWS CLI does not have a way to authenticate via username/password, only the online web console. While most organizations should enforce Multi-Factor Authentication (MFA) for their IAM console accounts, this is not always enforced. Combine bad user practices and a poor password policy, and you may find yourself with the ability to authenticate into the console.

## Success Criteria

- IAM Accounts configured without Multi-Factor Authentication (MFA)
- Poor password policy
- Poor user passwords

By default, AWS prompts to generate user passwords using a random secure string. However, user's might change these passwords and organizations may modify their password policy to be insecure (or a legacy AWS deployment that has had a poor password policy for a long time).

## Help

```
> $ GoAWSConsoleSpray --help

        GoAWSConsoleSpray is used to spray AWS IAM console credentials from
        a list of usernames and passwords. The tool will detect valid usernames
        if those accounts are configured with MFA enabled. If no MFA, it will 
        detect successful login attempts. Accounts configured with MFA cannot
        be sprayed at this time.

        Example: GoAWSConsoleSpray -u users.txt -p pws.txt -a 123456789012

Usage:
  GoAWSConsoleSpray [flags]

Flags:
  -a, --accountID string   AWS Account ID (required unless username is ARN)
  -d, --delay int          Optional Time Delay between login requests
  -h, --help               help for GoAWSConsoleSpray
  -j, --jitter int         Optional Time Jitter Between Requests (0 to n)
  -p, --passfile string    Password string or file (required)
  -x, --proxy string       HTTP or Socks proxy URL & Port. Schema: proto://ip:port
  -z, --sleep int          Optional Time to sleep between spraying each a password 
  -s, --stopOnSuccess      Stop password spraying on successful hit
  -U, --userAgent string   Optional User-Agent header (default "GoAWSConsoleSpray")
  -u, --userfile string    Username string or file (required) can be user, arn, or acctId:user format
  -w, --workers int        Optional Time to sleep between password requests (default 5)
```

## Usage

`./GoAWSConsoleSpray -a ACCOUNTID -u users.txt -p pws.txt`

## Install

Requires go 1.17+

`go install github.com/confused-binary/GoAWSConsoleSpray@latest`

## Build

`git clone git@github.com:confused-binary/GoAWSConsoleSpray.git`

Download project dependencies: `make dep`

Use the makefile to build the target version, e.g.: `make linux`, `make darwin`, `make windows`

## Detection

This is not stealthy and it is not trying to be stealthy. This is very, very loud. All AWS IAM user and root sign-in events are logged in [CloudTrail by default](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html#cloudtrail-aws-console-sign-in-events-iam-user-failure). Additionally, AWS may actually block your IP address if you try to send too many requests. 

You may want to look into using other projects that use Amazon's AWS Gateway or Lambda that can help distribute your traffic. You should be able to chain this project easily with any of those with a bit of customization (point sign-in URL at AWS Gateway instead of AWS authenticate).
