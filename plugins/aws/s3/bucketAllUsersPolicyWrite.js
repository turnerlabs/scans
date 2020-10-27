var async = require('async');
var helpers = require('../../../helpers/aws/');
var minimatch = require('minimatch');
const { writePermissions } = require('./s3Permissions');

function matchedPermissions(policyActions, permissions) {
    return permissions.filter(perm => {
        return policyActions.find(action => minimatch(perm, action));
    });
}

function noWritePermissions(statement) {
    if (statement.Action) {
        var actions = typeof statement.Action === 'string' ? [statement.Action] : statement.Action;
        var grantedWriteActions = matchedPermissions(actions, writePermissions);
        if (!grantedWriteActions.length) {
            return true;
        }
    } else if (statement.NotAction) {
        var notActions = typeof statement.NotAction === 'string' ? [statement.NotAction] : statement.NotAction;
        var deniedWriteActions = matchedPermissions(notActions, writePermissions);
        if (deniedWriteActions.length === writePermissions.length) {
            return true;
        }
    }
    return false;
}

module.exports = {
    title: 'S3 Bucket All Users Policy Write',
    category: 'S3',
    description: 'Ensures S3 bucket policies do not allow global write permissions',
    more_info: 'S3 buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to known users or accounts.',
    recommended_action: 'Remove wildcard principals from the bucket policy statements.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
    },
    settings: {
        s3_trusted_ip_cidrs: {  // TODO
            name: 'S3 Trusted Ip Cidrs',
            description: 'TBD',
            regex: '^(true|false)$',
            default: 'false'
        },
        s3_public_tag: {  // TODO
            name: 'S3 Public Tag',
            description: 'if this is set, and the bucket has a tag with this key, include the tag key/value in the message',
            regex: '^(true|false)$',
            default: 'false'
        },
        allowed_accounts: {  // TODO
            name: 'Allowed accounts',
            description: 'allowed accounts for sourceArn and sourceAccount condition keys',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, 'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        for (i in listBuckets.data) {
            var bucket = listBuckets.data[i];

            var bucketResource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 0, 'No additional bucket policy found', 'global', bucketResource);
            } else if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, 'global', bucketResource);
            } else {
                try {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                    // getBucketPolicy.data.Policy = policyJson;

                    if (!policyJson || !policyJson.Statement) {
                        helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, 'global', bucketResource);
                    } else if (!policyJson.Statement.length) {
                        helpers.addResult(results, 0, 'Bucket policy does not contain any statements', 'global', bucketResource);
                    } else {
                        var policyMessage = [];
                        var policyResult = 0;

                        for (s in policyJson.Statement) {
                            var statement = policyJson.Statement[s];

                            if (statement.Effect && statement.Effect === 'Allow') {
                                if (statement.Principal) {
                                    if (noWritePermissions(statement)) continue;

                                    var starPrincipal = false;
                                    if (typeof statement.Principal === 'string' && statement.Principal === '*') {
                                        starPrincipal = true;
                                    } else if (typeof statement.Principal === 'object') {
                                        if (statement.Principal.Service && statement.Principal.Service === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.AWS && statement.Principal.AWS === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.length && statement.Principal.indexOf('*') > -1) {
                                            starPrincipal = true;
                                        }
                                    }

                                    if (starPrincipal) {
                                        if (statement.Condition) {
                                            if (policyResult < 1) policyResult = 1;
                                            policyMessage.push(`Principal * allowed to conditionally perform: ${statement.Action}`);
                                        } else {
                                            if (policyResult < 2) policyResult = 2;
                                            policyMessage.push(`Principal * allowed to perform: ${statement.Action}`);
                                        }
                                    }
                                }
                            }
                        }

                        if (!policyMessage.length) {
                            helpers.addResult(results, 0, 'Bucket policy does not contain any insecure allow statements', 'global', bucketResource);
                        } else {
                            helpers.addResult(results, policyResult, policyMessage.join(' '), 'global', bucketResource);
                        }
                    }
                } catch(e) {
                    helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON could not be parsed.`, 'global', bucketResource);
                }
            }
        }

        callback(null, results, source);
    }
};
