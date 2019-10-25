var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Encryption Enabled',
    category: 'RDS',
    description: 'Ensures at-rest encryption is setup for RDS instances',
    more_info: 'AWS provides at-read encryption for RDS instances which should be enabled to ensure the integrity of data stored within the databases.',
    link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    recommended_action: 'RDS does not currently allow modifications to encryption after the instance has been launched, so a new instance will need to be created with encryption enabled.',
    apis: ['RDS:describeDBInstances'],
    compliance: {
        hipaa: 'All data in HIPAA environments must be encrypted, including ' +
                'data at rest. RDS encryption ensures that this HIPAA control ' +
                'is implemented by providing KMS-backed encryption for all RDS ' +
                'data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. RDS ' +
             'encryption should be enabled for all instances storing this type ' +
             'of data.'
    },
    settings: {
        rds_encryption_tag_key: {
            name: 'RDS Encryption Tag Key',
            description: 'Only enforce encryption on RDS instances with this tag and a value that matches the regex',
            regex: '^.*$',
            default: '',
        },
        rds_encryption_tag_value: {
            name: 'RDS Encryption Tag Value',
            description: 'Only enforce encryption on RDS instances with this tag and a value that matches the regex',
            regex: '^.*$',
            default: '^.*$'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var tagKey = settings.rds_encryption_tag_key || this.settings.rds_encryption_tag_key.default
        var tagValueRegex = RegExp(this.settings.rds_encryption_tag_value.default);
        try {
            var tagValueRegex = RegExp(settings.rds_encryption_tag_value || this.settings.rds_encryption_tag_value.default);
        } catch (err) {
            helpers.addResult(results, 3, err.message, 'global', this.settings.rds_encryption_tag_value.name);
        }

        async.each(regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source, ['rds', 'describeDBInstances', region]);
            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3, 'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            async.each(describeDBInstances.data, function(db, dcb) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var dbResource = db.DBInstanceArn;
                var kmsKey = db.KmsKeyId;

                if (settings.rds_encryption_tag_key !== '') { // if true, we need to look at tags
                    var listTagsForResource = helpers.addSource(cache, source, ['rds', 'listTagsForResource', region, dbResource]);

                    if (!listTagsForResource || listTagsForResource.err) {
                        var tagErr = helpers.addError(listTagsForResource);
                        if (tagErr !== 'The TagList does not exist') {
                            helpers.addResult(results, 3, `Error querying instances tags for ${dbName}: ${helpers.addError(listTagsForResource)}`, 'global', dbResource);
                        }
                        return dcb();
                    }

                    if (listTagsForResource.data && listTagsForResource.data.TagList) {
                        var targetTag = listTagsForResource.data.TagList.find(({ Key, Value }) => Key === tagKey && tagValueRegex.test(Value));
                        if (!targetTag) {
                            return dcb(); // the tag is not found
                        }
                    }
                }

                if (db.StorageEncrypted) {
                    helpers.addResult(results, 0, 'Encryption at rest is enabled via KMS key: ' + (kmsKey || 'Unknown'), region, dbResource);
                } else {
                    helpers.addResult(results, 2, 'Encryption at rest is not enabled', region, dbResource);
                }
            }, rcb);
        }, function(){
            callback(null, results, source);
        });
    }
};
