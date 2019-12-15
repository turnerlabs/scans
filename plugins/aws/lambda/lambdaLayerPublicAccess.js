var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Layers Public Access',
    category: 'Lambda',
    description: 'Ensures Lambda layers are not accessible globally.',
    more_info: 'The Lambda layer policy should not allow public download of the layer.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.htm',
    recommended_action: 'Correct the Lambda layer policy to prevent access from the public.',
    apis: ['Lambda:listLayers', 'Lambda:listLayerVersions', 'Lambda:getLayerVersionPolicy'],
    settings: {
        lambda_layer_allowed_account_ids: {
            name: 'Lambda Layer Allowed Account Ids',
            description: 'Allowed account ids. Providing no accounts in the settings allows any individual account.',
            regex: '^((\\d{12})(,\\d{12})*)?$',
            default: '',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {};

        if (settings.lambda_layer_allowed_account_ids) {
            config.lambda_layer_allowed_account_ids = settings.lambda_layer_allowed_account_ids.split(",");
        } else {
            config.lambda_layer_allowed_account_ids = [];
        }

        async.each(regions.lambda, function(region, rcb){
            var listLayers = helpers.addSource(cache, source,
                ['lambda', 'listLayers', region]);
            if (!listLayers) return rcb();

            if (listLayers.err || !listLayers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lambda layers: ' + helpers.addError(listLayers), region);
                return rcb();
            }

            if (!listLayers.data.length) {
                helpers.addResult(results, 0, 'No Lambda layers found associated with Function', region);
                return rcb();
            }

            for (f in listLayers.data) {
                var layer = listLayers.data[f];
                var arn = layer.LayerName;

                var policies = helpers.addSource(cache, source,
                    ['lambda', 'getLayerVersionPolicy', region, layer.LayerName]);

                if (!policies) {
                    helpers.addResult(results, 3, 'Error querying for policy for a layer', region, arn);

                } else if (policies.err) {
                    if (policies.err.code && policies.err.code == 'ResourceNotFoundException') {
                        helpers.addResult(results, 0, 'Layer does not have an access policy', region, arn);
                    } else {
                        helpers.addResult(results, 3, 'Error querying for Lambda layer policy: ' + helpers.addError(policies), region, arn);
                    }

                } else if (policies.data) {

                    var foundGlobal = false;
                    var foundNotAllowed = false;

                    policies.data.forEach(policy => {
                        policy.data.Statement.forEach(statement => {

                            if (statement.Principal) {
                                var isGlobal = helpers.globalPrincipal(statement.Principal);
    
                                if (isGlobal) {
                                    foundGlobal = true
    
                                }
    
                                if (config.lambda_layer_allowed_account_ids.length && statement.Principal.AWS) {
                                    var containsNotAllowed = true;
                                    config.lambda_layer_allowed_account_ids.forEach(id => {
                                        if (statement.Principal.AWS.includes(id)) {
                                            containsNotAllowed = false;
                                        }
                                    })
    
                                    foundNotAllowed = containsNotAllowed;
                                } 
    
                            }
    
                        });
                    });

                    if (foundGlobal.length) {
                        helpers.addResult(results, 2, 'Layer policy statement allows global access to actions', region, arn);
                    } else if (foundNotAllowed) {
                        helpers.addResult(results, 2, 'Layer policy statement allows non-approved users access to actions', region, arn);
                    } else {
                        helpers.addResult(results, 0, 'Layer policy statement does not allow global or non-approved access', region, arn);
                    }


                } else {
                    helpers.addResult(results, 3, 'Unable to obtain Lambda layer policy', region, arn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
