var async = require('async');
var helpers = require('../../../helpers/aws');
const encryptionLevelMap = {
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5
};

function getEncryptionLevel(kmsKey) {
    return kmsKey.Origin === 'AWS_CLOUDHSM' ? 'cloudhsm' :
           kmsKey.Origin === 'EXTERNAL' ? 'externalcmk' :
           kmsKey.KeyManager === 'CUSTOMER' ? 'awscmk' : 'awskms'
}

module.exports = {
    title: 'SSM Encrypted Parameters',
    category: 'SSM',
    description: 'Ensures SSM Parameters are encrypted',
    more_info: 'SSM Parameters should be encrypted. This allows their values to be used by approved systems, while restricting access to other users of the account.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-about.html#sysman-paramstore-securestring',
    recommended_action: 'Recreate unencrypted SSM Parameters with Type set to SecureString.',
    apis: ['SSM:describeParameters', 'STS:getCallerIdentity', 'KMS:listAliases', 'KMS:describeKeys'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest',
        pci: 'PCI requires proper encryption of cardholder data at rest. SSM ' +
             'encryption should be enabled for all parameters storing this type ' +
             'of data.'
    },
    settings: {
        ssm_encryption_level: {
            name: 'SSM Minimum Encryption Level',
            description: 'In order (lowest to highest) \
                sse=Server-Side Encryption; \
                awskms=AWS-managed KMS; \
                awscmk=Customer managed KMS; \
                externalcmk=Customer managed externally sourced KMS; \
                cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(sse|awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'sse',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var desiredEncryptionLevelString = settings.ssm_encryption_level || this.settings.ssm_encryption_level.default
        if(!desiredEncryptionLevelString.match(this.settings.ssm_encryption_level.regex)) {
            helpers.addResult(results, 3, 'Settings misconfigured for SSM Encryption Level.');
            return callback(null, results, source);
        }

        var desiredEncryptionLevel = encryptionLevelMap[desiredEncryptionLevelString]
        var currentEncryptionLevelString, currentEncryptionLevel
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ssm, function(region, rcb){
            var describeParameters = helpers.addSource(cache, source,
                ['ssm', 'describeParameters', region]);

            if (!describeParameters) return rcb();

            if (describeParameters.err || !describeParameters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Parameters: ' + helpers.addError(describeParameters), region);
                return rcb();
            }

            if (!describeParameters.data.length) {
                helpers.addResult(results, 0, 'No Parameters present', region);
                return rcb();
            }

            async.each(describeParameters.data, function(param, pcb) {
                var paramName = param.Name.charAt(0) === '/' ? param.Name.substr(1) : param.Name;
                var arn = 'arn:aws:ssm:' + region + ':' + accountId + ':parameter/' + paramName;

                if (param.Type != "SecureString") {
                    helpers.addResult(results, 2, 'Non-SecureString Parameters present', region, arn)
                } else {
                    var keyId
                    if(param.KeyId.includes("alias")) {
                        var aliases = helpers.addSource(cache, source, ['kms', 'listAliases', region]);
                        if (!aliases) {
                            helpers.addResult(results, 3, 'Unable to query for Aliases', region);
                            return pcb();
                        }

                        if (aliases.err || !aliases.data) {
                            helpers.addResult(results, 3, 'Unable to query for Aliases: ' + helpers.addError(aliases), region);
                            return pcb();
                        }

                        if (!aliases.data.length) {
                            helpers.addResult(results, 3, 'No Aliases present, however one is required.', region);
                            return pcb();
                        }

                        async.filter(aliases.data, function(alias, acb){
                            acb(null, alias.AliasName === param.KeyId)
                        }, function(err, val){
                            if(val.length === 0) {
                                helpers.addResult(results, 3, 'Unable to locate alias: ' + param.KeyId, region);
                                return pcb();
                            }
                            keyId = val[0].TargetKeyId
                        })
                    } else {
                        keyId = param.KeyId.split("/")[1]
                    }

                    var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, keyId]);

                    if(!describeKey) {
                        helpers.addResult(results, 3, 'Unable locate KMS key for describeKey: ' + keyId, region);
                        return pcb();
                    }
                    if (describeKey.err || !describeKey.data) {
                        helpers.addResult(results, 3, 'Unable to query for KMS Key: ' + helpers.addError(describeKey), region);
                        return pcb();
                    }

                    currentEncryptionLevelString = getEncryptionLevel(describeKey.data.KeyMetadata)
                    currentEncryptionLevel = encryptionLevelMap[currentEncryptionLevelString]

                    if (currentEncryptionLevel < desiredEncryptionLevel) {
                        helpers.addResult(results, 1, `SSM Param is encrypted to ${currentEncryptionLevelString}, which is lower than the desired ${desiredEncryptionLevelString} level.`, region, arn);
                    } else {
                        helpers.addResult(results, 0, `SSM Param is encrypted to a minimum of ${desiredEncryptionLevelString}`, region, arn);
                    }
                }
                return pcb()
            })

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
