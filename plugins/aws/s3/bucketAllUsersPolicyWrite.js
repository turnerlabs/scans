var helpers = require('../../../helpers/aws/');
const { makeBucketPolicyResultMessage, evaluateConditions, evaluateStatement } = require('../../../helpers/aws/s3/bucketPolicyEvaluation');
const {writePermissions} = require('./s3Permissions');

function getSpecificTag(bucketTaggingInfo, targetTag) {
    if (bucketTaggingInfo && bucketTaggingInfo.TagSet) {
        for (let tagInfo of bucketTaggingInfo.TagSet) {
            if (targetTag === tagInfo.Key) {
                return tagInfo.Key.concat(':', tagInfo.Value);
            }
        }
    }
    return '';
}

function evaluateBucketPolicy(policy, metadata, config) {
    let results = {
        failingOperatorKeyValueCombinations: [],
        unRecognizedOperatorKeyCombinations: [],
        numberAllows: 0,
        numberDenies: 0,
        numberFailStatements: 0,
        unconditionalMessages: []
    };
    for (let s in policy.Statement) {
        let statement = policy.Statement[s];
        const statementResults = evaluateStatement(statement, metadata, config);
        if (!statementResults.pass) {
            if (!statement.Condition) {
                results.unconditionalMessages.push(`Principal * unconditionally allowed to perform: ${statement.Action}`);
                results.numberFailStatements += 1;
            }
            else {
                const conditionEvaluationResults = evaluateConditions(statement, metadata, config);
                conditionEvaluationResults.failingOperatorKeyValueCombinations.forEach(item => results.failingOperatorKeyValueCombinations.push(JSON.parse(item)));
                conditionEvaluationResults.unRecognizedOperatorKeyCombinations.forEach(item => results.unRecognizedOperatorKeyCombinations.push(item));
                if (!conditionEvaluationResults.pass) results.numberFailStatements += 1;
            }
        }
        if (statementResults.isDeny) results.numberDenies += 1;
        if (statementResults.isAllow) results.numberAllows += 1;

    }
    return results;
}

module.exports = {
    title: 'S3 Bucket All Users Policy Write',
    category: 'S3',
    description: 'Ensures S3 bucket policies do not allow global write permissions',
    more_info: 'S3 buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to known users or accounts.',
    recommended_action: 'Remove wildcard principals from the bucket policy statements.',
    link: 'https://docs.aws.amazon.com/AmazonS3/latest/dev/using-iam-policies.html',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'S3:getBucketTagging', 'EC2:describeVpcEndpoints', 'EC2:describeVpcs', 'STS:getCallerIdentity'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
    },
    settings: {
        s3_trusted_ip_cidrs: {
            name: 'S3 Trusted Ip Cidrs',
            description: 'array of strings (or comma-separated string of cidrs) representing valid cidr ranges for conditions involving IpAddress',
            default: [],
            regex: /((25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\.(25[0-5]|2[0-4]\d|[01]?\d\d?)\/\d{1,2},?)*/
        },
        s3_public_tags: {
            name: 'S3 Public Tags',
            description: 'if this is set, and the bucket has this tag, include the tag key/value in the message',
            default: '',
            regex: /^\w{1,128}$/  // length cannot be outside of [1,128]
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_trusted_ip_cidrs: settings.s3_trusted_ip_cidrs || this.settings.s3_trusted_ip_cidrs.default,
            s3_public_tags: settings.s3_public_tags || this.settings.s3_public_tags.default,
            validPermissions: writePermissions,
        };
        if (typeof config.s3_trusted_ip_cidrs === 'string') config.s3_trusted_ip_cidrs = config.s3_trusted_ip_cidrs.split(',');
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);
        var getCallerIdentity = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region]);
        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err) {
            helpers.addResult(results, 3, 'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }
        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }
        if (getCallerIdentity.err || !getCallerIdentity.data) {
            helpers.addResult(results, 3, 'Unable to query for caller identity: ' + helpers.addError(getCallerIdentity));
            return callback(null, results, source);
        }
        if (cache.ec2.describeVpcEndpoints.err) {
            helpers.addResult(results, 3, 'Unable to query for vpc endpoints: ' + helpers.addError(cache.ec2.describeVpcEndpoints));
            return callback(null, results, source);
        }
        if (cache.ec2.describeVpcs.err) {
            helpers.addResult(results, 3, 'Unable to query for vpcs: ' + helpers.addError(cache.ec2.describeVpcs));
            return callback(null, results, source);
        }
        let describeVpcEndpoints = {
            data: []
        };
        let describeVpcs = {
            data: []
        };
        Object.values(cache.ec2.describeVpcEndpoints).forEach(value => {
            // collect vpc endpoints from all regions. ignore errors in a single region.
            if (value.data) describeVpcEndpoints.data.push(...value.data);
        });
        Object.values(cache.ec2.describeVpcs).forEach(value => {
            // collect vpc info from all regions. ignore errors in a single region.
            if (value.data) describeVpcs.data.push(...value.data);
        });
        for (var i in listBuckets.data) {
            var bucket = listBuckets.data[i];
            if (!bucket.Name) continue;

            var bucketResource = `arn:aws:s3:::${bucket.Name}`;

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);
            var getBucketTagging = helpers.addSource(cache, source, ['s3', 'getBucketTagging', region, bucket.Name]);
            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 0, 'No additional bucket policy found', 'global', bucketResource);
            } else if (!getBucketPolicy || getBucketPolicy.err || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, 'global', bucketResource);
            } else {
                try {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);

                    if (!policyJson || !policyJson.Statement) {
                        helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, 'global', bucketResource);
                    } else if (!policyJson.Statement.length) {
                        helpers.addResult(results, 0, 'Bucket policy does not contain any statements', 'global', bucketResource);
                    } else {
                        var metadata = {};
                        if (describeVpcEndpoints.data) metadata.describeVpcEndpoints = describeVpcEndpoints.data;
                        if (describeVpcs.data) metadata.describeVpcs = describeVpcs.data;
                        if (getCallerIdentity.data) metadata.getCallerIdentity = getCallerIdentity.data;
                        const bucketResults = evaluateBucketPolicy(policyJson, metadata, config);
                        let message = 'policy not recognized by plugin logic';
                        let statusCode = 3;
                        if (bucketResults.numberFailStatements > 0) {
                            if (bucketResults.unconditionalMessages.length > 0) {
                                // public open statements without condition
                                message = bucketResults.unconditionalMessages.join(' ');
                                message += `\n Number of denies: ${bucketResults.numberDenies.toString()}`;
                                message += `\n Number of allows: ${bucketResults.numberAllows.toString()}`;
                                statusCode = 2;
                            }
                            else if (bucketResults.failingOperatorKeyValueCombinations.length > 0) {
                                message = makeBucketPolicyResultMessage(bucketResults);
                                statusCode = 1;
                            }
                            else if (bucketResults.unRecognizedOperatorKeyCombinations.length > 0) {
                                message = makeBucketPolicyResultMessage(bucketResults);
                                statusCode = 1;
                            }
                            // NOTE else clause intentionally omitted
                        }
                        else {
                            message = 'Bucket policy does not contain any insecure allow statements';
                            statusCode = 0;
                        }
                        if (config.s3_public_tags) {
                            let tag = getSpecificTag(getBucketTagging.data, config.s3_public_tags);
                            if (tag) message += '\nThe bucket has public tag ' + tag;
                        }
                        helpers.addResult(results, statusCode, message, 'global', bucketResource);
                    }
                } catch(e) {
                    helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON could not be parsed.`, 'global', bucketResource);
                }
            }
        }

        callback(null, results, source);
    }
};
