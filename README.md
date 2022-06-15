# GoAWSConsoleSpray

GoAWSConsoleSpray is a tool that can be used to spray AWS IAM Console Credentials in order to identify a valid login for a user account. The AWS CLI does not have a way to authenticate via username/password, only the online web console. While most organizations should enforce Multi-Factor Authentication (MFA) for their IAM console accounts, this is not always enforced. Combine bad user practices and a poor password policy, and you may find yourself with the ability to authenticate into the console.

## Success Criteria

- IAM Accounts configured without Multi-Factor Authentication (MFA)
- Poor password policy
- Poor user passwords

By default, AWS prompts to generate user passwords using a random secure string. However, user's might change these passwords and organizations may modify their password policy to be insecure (or a legacy AWS deployment that has had a poor password policy for a long time).

## Usage

`./GoAWSConsoleSpray -a ACCOUNTID -u users.txt -p pws.txt`

## Install

Requires go 1.17+

`go install github.com/WhiteOakSecurity/GoAWSConsoleSpray@latest`

## Build

`git clone git@github.com:WhiteOakSecurity/GoAWSConsoleSpray.git`

Download project dependencies: `make dep`

Use the makefile to build the target version, e.g.: `make linux`, `make darwin`, `make windows`

## Detection

This is not stealthy and it is not trying to be stealthy. This is very, very loud. All AWS IAM user and root sign-in events are logged in [CloudTrail by default](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html#cloudtrail-aws-console-sign-in-events-iam-user-failure). Additionally, AWS may actually block your IP address if you try to send too many requests. 

You may want to look into using other projects that use Amazon's AWS Gateway or Lambda that can help distribute your traffic. You should be able to chain this project easily with any of those with a bit of customization (point sign-in URL at AWS Gateway instead of AWS authenticate).