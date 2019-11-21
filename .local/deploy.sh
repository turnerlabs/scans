#!/bin/bash
set -euxo pipefail
export ARTIFACT_BUCKET=trek10-sam
export STACK_NAME=cloudsploit-test
export DEFAULT_ROLE_NAME=cloudsploit-security-scanner-CloudSploitRole-1JP2J7H7TU647
export SECRETS_MANAGER_PREFIX=cloudsploit
export BUCKET_NAME=cloudsploit-trek10-rfarina
export BUCKET_PREFIX="cloudsploit"
export CREATE_BUCKET=yes
export SNS_TOPIC=arn:aws:sns:us-east-1:454679818906:cloudsploit-test
export SCHEDULE=""
export SCHEDULED_ACCOUNT_ID=""
export SCHEDULED_ROLE_NAME=""
export SCHEDULED_EXTERNAL_ID=""

./cloudformation/deploy.sh