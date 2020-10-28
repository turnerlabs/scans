var helpers = require('../../../helpers/aws/');
const { evaluateBucketPolicy } = require('../../../helpers/aws/s3/bucketPolicyEvaluation');


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
            description: 'array of strings representing valid cidr ranges for conditions involving IpAddress',
            default: ['']
        },
        s3_public_tags: {
            name: 'S3 Public Tags',
            description: 'if this is set, and the bucket has this tag, include the tag key/value in the message',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            s3_trusted_ip_cidrs: settings.s3_trusted_ip_cidrs || this.settings.s3_trusted_ip_cidrs.default,
            s3_public_tags: settings.s3_public_tags || this.settings.s3_public_tags.default,
            mustContainRead: false,
            mustContainWrite: true
        };
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listBuckets = helpers.addSource(cache, source, ['s3', 'listBuckets', region]);
        var describeVpcEndpoints = helpers.addSource(cache, source, ['ec2', 'describeVpcEndpoints', region]);
        var describeVpcs = helpers.addSource(cache, source, ['ec2', 'describeVpcs', region]);
        var getCallerIdentity = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3, 'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

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
                        if (getBucketTagging.data) metadata.getBucketTagging = getBucketTagging.data;
                        if (describeVpcEndpoints.data) metadata.describeVpcEndpoints = describeVpcEndpoints.data;
                        if (describeVpcs.data) metadata.describeVpcs = describeVpcs.data;
                        if (getCallerIdentity.data) metadata.getCallerIdentity = getCallerIdentity.data;
                        const bucketResults = evaluateBucketPolicy(policyJson, metadata, config);
                        if (bucketResults.numberFailStatements > 0) {
                            const message = 'conditions:' + JSON.stringify(bucketResults.nonPassingConditions) +
                                ' numAllows:' + String(bucketResults.numberAllows) + ' numDenies:' +
                                String(bucketResults.numberDenies) + ' numberFailStatements:' +
                                String(bucketResults.numberFailStatements) + ' tag:' + bucketResults.tag;
                            helpers.addResult(results, 2, message, 'global', bucketResource);
                        }
                        else {
                            helpers.addResult(results, 0, 'Bucket policy does not contain any insecure allow statements', 'global', bucketResource);
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
