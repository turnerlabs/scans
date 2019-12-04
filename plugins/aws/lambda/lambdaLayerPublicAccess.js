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

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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
                helpers.addResult(results, 0, 'No Lambda layers found', region);
                return rcb();
            }

            for (f in listLayers.data) {
                var layer = listLayers.data[f];
                var arn = layer.LayerName;

                var policies = helpers.addSource(cache, source,
                    ['lambda', 'getLayerVersionPolicy', region, layer.LayerName]);

                var result = [0, ''];

                if (!policies) {
                    result = [3, 'Error querying for policies for a layer'];
                } else if (policies.err) {
                    if (policies.err.code && policies.err.code == 'ResourceNotFoundException') {
                        result = [0, 'Layer does not have an access policy'];
                    } else {
                        result = [3, 'Error querying for Lambda layer policy: ' + helpers.addError(policies)];
                    }
                } else if (policy.data) {

                    policies.forEach(function(policy) {
                        var normalized = helpers.normalizePolicyDocument(policy.data.Policy);

                        var found = [];
                        for (n in normalized) {
                            var statement = normalized[n];
                            if (statement.Principal) {
                                var isGlobal = helpers.globalPrincipal(statement.Principal);
                                if (isGlobal) {
                                    for (s in statement.Action) {
                                        if (found.indexOf(statement.Action[s]) == -1) {
                                            found.push(statement.Action[s]);
                                        }
                                    }
                                }
                            }
                        }

                        if (found.length) {
                            result = [2, 'Layer policy allows global access to actions: ' + found.join(', ')];
                        } else {
                            result = [0, 'Layer policy does not allow global access'];
                        }
                    });
                    
                } else {
                    result = [3, 'Unable to obtain Lambda layer policy'];
                }

                helpers.addResult(results, result[0], result[1], region, arn);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
