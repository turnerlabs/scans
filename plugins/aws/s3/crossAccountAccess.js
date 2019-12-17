var helpers = require('../../../helpers/aws');

const ANY = 'any';

module.exports = {
    title: 'S3 Bucket Access From Unpermitted Accounts',
    category: 'S3',
    description: 'S3 Bucket Policies must not allow read/write access from unpermitted AWS accounts',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'STS:getCallerIdentity'],
    settings: {
        s3_account_whitelist: {
            name: 'S3 Policy Account Whitelist',
            description: `A comma-separated list of AWS Account IDs that S3 bucket policies are allowed to trust. ("${ANY}" = any specific account, "" = no cross-account)`,
            regex: '^(|\\d{0,12}(,\\d{12})*|\\*)$',
            default: ANY,
        },
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

        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);
        var s3AccountWhitelist = settings.s3_account_whitelist || this.settings.s3_account_whitelist.default;

        for (bucket of listBuckets.data) {
            if (!bucket.Name) continue;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source, ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 0, 'No bucket policy found', 'global', bucketResource);
            } else if (getBucketPolicy.err || !getBucketPolicy || !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: ${helpers.addError(getBucketPolicy)}`, 'global', bucketResource);
            } else {
                try {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                } catch(e) {
                    helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON could not be parsed.`, 'global', bucketResource);
                    continue;
                }

                if (!policyJson || !policyJson.Statement) {
                    helpers.addResult(results, 3, `Error querying for bucket policy for bucket: ${bucket.Name}: Policy JSON is invalid or does not contain valid statements.`, 'global', bucketResource);
                } else if (!policyJson.Statement.length) {
                    helpers.addResult(results, 0, 'Bucket policy does not contain any statements', 'global', bucketResource);
                } else {
                    var crossAccountActions = [];

                    var statements = helpers.normalizePolicyDocument(policyJson);

                    for (s in statements) {
                        var statement = statements[s];

                        if (!statement.Effect || statement.Effect !== 'Allow' || !statement.Principal) {
                            continue;
                        }

                        if (s3AccountWhitelist === ANY) { // trust any
                            continue;
                        } else if (crossAccountPrincipal(statement.Principal, accountId, s3AccountWhitelist)) {
                            for (a in statement.Action) {
                                if (!crossAccountActions.includes(statement.Action[a])) {
                                    crossAccountActions.push(statement.Action[a]);
                                }
                            }
                        }
                    }

                    if (crossAccountActions.length) {
                        helpers.addResult(results, 2, `The bucket policy allows cross-account access to unpermitted accounts, action(s): ${crossAccountActions}`, region, bucketResource);
                    } else if (s3AccountWhitelist === ANY) {
                        helpers.addResult(results, 0, 'All accounts are trusted', region, bucketResource);
                    } else {
                        helpers.addResult(results, 0, 'The bucket policy does not allow cross-account access to unpermitted accounts.', region, bucketResource);
                    }
                }
            }
        }
        callback(null, results, source);
    }
};

function crossAccountPrincipal(principal, accountId, whitelist) {
    var accountList = whitelist.split(',');
    if (typeof principal === 'string' && /^[0-9]{12}$/.test(principal) && principal !== accountId && !accountList.includes(principal)) {
        return true;
    }

    var awsPrincipals = principal.AWS || [];
    if(!Array.isArray(awsPrincipals)) {
        awsPrincipals = [awsPrincipals];
    }

    for (a in awsPrincipals) {
        const principalAccount = awsPrincipals[a].split('arn:aws:iam::')[1].split(':')[0];
        if (principalAccount !== accountId && !whitelist.includes(principalAccount)) {
            return true;
        }
    }

    return false;
}
