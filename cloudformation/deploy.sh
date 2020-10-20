#!/bin/bash
set -euxo pipefail

GIT_REPO="$(git config --get remote.origin.url)"
GIT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
GIT_COMMIT_ID="$(git rev-parse --short HEAD)"
export GIT_COMMIT_ID GIT_BRANCH GIT_REPO

npm install

aws cloudformation package \
  --s3-bucket ${ARTIFACT_BUCKET} \
  --template-file ./cloudformation/template.yaml \
  --output-template-file ./template.packaged.yaml

aws cloudformation deploy \
  --template-file ./template.packaged.yaml \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --stack-name ${STACK_NAME} \
  --parameter-overrides \
    GitRepo="${GIT_REPO}" \
    GitBranch="${GIT_BRANCH}" \
    GitCommitId="${GIT_COMMIT_ID}" \
    DefaultRoleName=${DEFAULT_ROLE_NAME} \
    SecretsManagerPrefix=${SECRETS_MANAGER_PREFIX} \
    BucketName=${BUCKET_NAME} \
    BucketPrefix=${BUCKET_PREFIX} \
    CreateBucket=${CREATE_BUCKET} \
    SNSTopic=${SNS_TOPIC} \
    Schedule=${SCHEDULE} \
    ScheduledAccountId=${SCHEDULED_ACCOUNT_ID} \
    ScheduledRoleName=${SCHEDULED_ROLE_NAME} \
    ScheduledExternalId=${SCHEDULED_EXTERNAL_ID}
