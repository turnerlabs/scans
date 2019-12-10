var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Sharing is not used',
    category: 'EC2',
    description: 'VPC Sharing is not used as it violates the principal of Network Segmentation',
    apis: ['RAM:listResources'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        async.each(regions.ram, function(region, rcb) {
            var listResources = helpers.addSource(cache, source, ['ram', 'listResources', region]);

            if (!listResources) return rcb();

            if (listResources.err || !listResources.data) {
                helpers.addResult(results, 3, `Unable to query RAM for resources: ${helpers.addError(listResources)}`, region);
                return rcb();
            }

            const invalidResources = listResources.data.filter(resource => ['ec2:Subnet', 'ec2:TransitGateway', 'ec2:TrafficMirrorTarge'].includes(resource.type));
            if (invalidResources.length) {
                for (let resource of invalidResources) {
                    helpers.addResult(results, 2, 'Shared VPC resource', region, resource.arn);
                }
            } else {
                helpers.addResult(results, 0, 'No Shared VPC resources', region);
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
};
