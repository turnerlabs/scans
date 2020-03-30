var assert = require('assert');
var expect = require('chai').expect;
var vpcSharing = require('./vpcSharing')

const createCache = (sharedResources) => {
    return {
        ram: {
            listResources: {
                'us-east-1': {
                    data: sharedResources,
                },
            },
        },
    };
};

describe('vpcSharing', function () {
    describe('run', function () {
        it('should PASS if no shared resources', function (done) {
            const cache = createCache([]);
            vpcSharing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

           it('should PASS if no shared VPCs', function (done) {
            const cache = createCache([{
                arn: 'arn:aws:ec2:us-east-1:123412341234:capacity-reservation/abc123',
                resourceShareArn: 'arn:aws:ram:us-east-1:123412341234:resource-share/abc123',
                type: 'ec2:CapacityReservation',
            }]);
            vpcSharing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if shared VPC', function (done) {
            const cache = createCache([{
                arn: 'arn:aws:ec2:us-east-1:123412341234:subnet/abc123',
                resourceShareArn: 'arn:aws:ram:us-east-1:123412341234:resource-share/abc123',
                type: 'ec2:Subnet',
            }]);
            vpcSharing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
    });
});
