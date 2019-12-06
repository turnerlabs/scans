
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
                            Version: '2012-10-17',
                            Id: 'default',
                            Statement: [
                                {
                                Sid: '999',
                                Effect: 'Allow',
                                Principal: users,
                                Action: 'lambda:GetLayerVersion',
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

            const cache = createCache({AWS: ["1231231231244", "1231231231245"]});

            lambdaLayerPublicAccess.run(cache, {allowed_ids: ["12312312312"]}, callback);
        })

    })

    describe('run', function () {
        it('should PASS if no allowed ids are set in settings', function (done) {

            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                done()
            }

            const cache = createCache({AWS: ["1231231231244", "1231231231245"]});

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
