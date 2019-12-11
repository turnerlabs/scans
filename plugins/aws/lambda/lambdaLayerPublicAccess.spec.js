
var assert = require('assert');
var expect = require('chai').expect;
var lambdaLayerPublicAccess = require('./lambdaLayerPublicAccess');

const createCache = (users) => {
    return {
        lambda: {
            listLayers: {
                'us-east-2': {
                    data: [{LayerName: "test-layer"}]
                }
            },
            getLayerVersionPolicy: {
                'us-east-2': {
                    "test-layer": {
                        data: {
                            Statement: [
                                {
                                Principal: users,
                                Resource: 'arn:aws:lambda:us-east-2:455679818906:layer:test-layer:1'
                                }
                            ]
                        }
                    }
                }
            }       
        }
    }
}

describe('lambdaLayerPublicAccess', function () {
    describe('run', function () {
        it('should FAIL when global user passed', function (done) {

            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            }

            const cache = createCache("*");

            lambdaLayerPublicAccess.run(cache, {}, callback);
        })

    })

    describe('run', function () {
        it('should FAIL when non-allowed ids passed', function (done) {

            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                done()
            }

            const cache = createCache({AWS: "arn:aws:lambda:us-east-2:231231553156"});

            lambdaLayerPublicAccess.run(cache, {lambda_layer_allowed_account_ids: "231231553155,231231583155"}, callback);
        })

    })

    describe('run', function () {
        it('should PASS if no allowed ids are set in settings', function (done) {

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            }

            const cache = createCache({AWS: "arn:aws:lambda:us-east-2:2312312"});

            lambdaLayerPublicAccess.run(cache, {}, callback);
        })

    })

    describe('run', function () {
        it('should PASS if no users or settings are passed', function (done) {

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            }

            const cache = createCache({});

            lambdaLayerPublicAccess.run(cache, {}, callback);
        })

    })
})
