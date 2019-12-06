var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var lambda = new AWS.Lambda(AWSConfig);
    async.eachLimit(collection.lambda.listLayers[AWSConfig.region].data, 15, function(layer, cb){
        collection.lambda.getLayerVersionPolicy[AWSConfig.region][layer.LayerName] = {};

        var params = {

            LayerName: layer.LayerName,
            VersionNumber: layer.LatestMatchingVersion.Version
        };

        lambda.getLayerVersionPolicy(params, function(err, data) {
            if (err) {
                collection.lambda.getLayerVersionPolicy[AWSConfig.region][layer.LayerName].err = err;
            }
            // convert the data to json object
            try {
                var policyData = JSON.parse(data.Policy);
            } catch(e) {
                var policyData = null;
            }
            
            collection.lambda.getLayerVersionPolicy[AWSConfig.region][layer.LayerName].data = policyData;
            cb();
        });
    }, function(){
        callback();
    });
};