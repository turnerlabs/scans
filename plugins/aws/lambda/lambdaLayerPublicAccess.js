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
        allowed_ids: []
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var config = {allowed_ids: settings.allowed_ids || this.settings.allowed_ids};

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

                var policy = helpers.addSource(cache, source,
                    ['lambda', 'getLayerVersionPolicy', region, layer.LayerName]);

                var result = [0, ''];

                if (!policy) {
                    result = [3, 'Error querying for policy for a layer'];
                } else if (policy.err) {
                    if (policy.err.code && policy.err.code == 'ResourceNotFoundException') {
                        result = [0, 'Layer does not have an access policy'];
                    } else {
                        result = [3, 'Error querying for Lambda layer policy: ' + helpers.addError(policy)];
                    }
                } else if (policy.data) {
                    var foundGlobal = [];
                    var foundNotAllowed = [];
                    var statement = policy.data.Statement[0];
                    var isGlobal = helpers.globalPrincipal(statement.Principal);

                    if (statement.Principal) {
                        if (isGlobal) {
                            if (foundGlobal.indexOf(statement.Action) == -1) {
                                foundGlobal.push(statement.Action);
                            }
                            
                        }

                        if (statement.Principal.AWS && Array.isArray(statement.Principal.AWS)) {
                            statement.Principal.AWS.forEach(function(item) {
                                if (config.allowed_ids.length && config.allowed_ids.indexOf(item) === -1) {
                                    foundNotAllowed.push(item);
                                }

                            });
                        } else if (statement.Principal.AWS) {
                            if (config.allowed_ids.length && config.allowed_ids.indexOf(statement.Principal.AWS) === -1) {
                                foundNotAllowed.push(item);
                            }

                        }

                    }
                    
                    if (foundGlobal.length) {
                        result = [2, 'Layer policy allows global access to actions: ' + foundGlobal.join(', ')];
                    } else if (foundNotAllowed.length) {
                        result = [2, 'Layer policy allows non-approved users access to actions: ' + foundNotAllowed.join(', ')];
                    } else {
                        result = [0, 'Layer policy does not allow global or non-approved access'];
                    }

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
