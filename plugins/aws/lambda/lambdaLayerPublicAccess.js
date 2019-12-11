var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Layers Public Access',
    category: 'Lambda',
    description: 'Ensures Lambda layers are not accessible globally.',
    more_info: 'The Lambda layer policy should not allow public download of the layer.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-layers.htm',
    recommended_action: 'Correct the Lambda layer policy to prevent access from the public.',
    apis: ['Lambda:listLayers', 'Lambda:getLayerVersionPolicy'],
    settings: {
        lambda_layer_allowed_account_ids: {
            name: 'Lambda Layer Allowed Account Ids',
            description: 'Allowed account ids. Providing no accounts in the settings allows any individual account.',
            regex: '(^$|(\d{12})(,\d{12})*)',
            default: [],
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
            config.lambda_layer_allowed_account_ids = this.settings.lambda_layer_allowed_account_ids.default;
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

                var policy = helpers.addSource(cache, source,
                    ['lambda', 'getLayerVersionPolicy', region, layer.LayerName]);

                var result = [0, ''];

                if (!policy) {
                    result = [3, 'Error querying for policy for a layer'];
                    helpers.addResult(results, result[0], result[1], region, arn);

                } else if (policy.err) {
                    if (policy.err.code && policy.err.code == 'ResourceNotFoundException') {
                        result = [0, 'Layer does not have an access policy'];
                    } else {
                        result = [3, 'Error querying for Lambda layer policy: ' + helpers.addError(policy)];
                    }

                    helpers.addResult(results, result[0], result[1], region, arn);

                } else if (policy.data) {
                    policy.data.Statement.forEach(statement => {
                        var foundGlobal = [];
                        var foundNotAllowed = true;

                        var isGlobal = helpers.globalPrincipal(statement.Principal);

                        if (statement.Principal) {
                            if (isGlobal) {
                                if (foundGlobal.indexOf(statement.Action) == -1) {
                                    foundGlobal.push(statement.Action);
                                }
                                
                            }

                            if (config.lambda_layer_allowed_account_ids.length && statement.Principal.AWS) {
                                config.lambda_layer_allowed_account_ids.forEach(id => {
                                    if (statement.Principal.AWS.includes(id)) {
                                        foundNotAllowed = false;
                                    }
                                })
                            } else {
                                foundNotAllowed = false;
                            }

                            if (foundGlobal.length) {
                                result = [2, 'Layer policy statement allows global access to actions'];
                            } else if (foundNotAllowed) {
                                result = [2, 'Layer policy statement allows non-approved users access to actions'];
                            } else {
                                result = [0, 'Layer policy statement does not allow global or non-approved access'];
                            }
                        }

                        helpers.addResult(results, result[0], result[1], region, arn);

                    });
                    
                } else {
                    result = [3, 'Unable to obtain Lambda layer policy'];
                    helpers.addResult(results, result[0], result[1], region, arn);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
