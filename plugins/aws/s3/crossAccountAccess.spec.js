var expect = require('chai').expect;
var crossAccountAccess = require('./crossAccountAccess');

const CURRENT_ACCOUNT = '111111111111';

const createCache = (trustedAccount) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2012-10-17',
                                Statement: [{
                                    Effect: 'Allow',
                                    Principal: {
                                        AWS: `arn:aws:iam::${trustedAccount}:root`,
                                    },
                                    Action: 's3:*',
                                    Resource: [
                                        'arn:aws:s3:::mybucket',
                                        'arn:aws:s3:::mybucket/*',
                                    ],
                                }]
                            }),
                        },
                    },
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: CURRENT_ACCOUNT,
                },
            },
        },
    };
};


const createCacheEmpty = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: CURRENT_ACCOUNT,
                },
            },
        },
    };
};

const createCacheTrustAllAWS = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketPolicy: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Policy: JSON.stringify({
                                Version: '2012-10-17',
                                Statement: [{
                                    Effect: 'Allow',
                                    Principal: {
                                        AWS: '*',
                                    },
                                    Action: 's3:*',
                                    Resource: [
                                        'arn:aws:s3:::mybucket',
                                        'arn:aws:s3:::mybucket/*',
                                    ],
                                }],
                            }),
                        },
                    },
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: CURRENT_ACCOUNT,
                },
            },
        },
    };
};

describe('crossAccountAccess', function () {
    describe('run', function () {
        it('should PASS if trusts the same account', function (done) {
            const cache = createCache(CURRENT_ACCOUNT);
            crossAccountAccess.run(cache, { s3_account_whitelist: '999999999999' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if trusts a non-whitelisted account', function (done) {
            const cache = createCache('2222222222222');
            crossAccountAccess.run(cache, { s3_account_whitelist: '999999999999' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if trusts all AWS', function (done) {
            const cache = createCacheTrustAllAWS();
            crossAccountAccess.run(cache, { s3_account_whitelist: '999999999999' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no buckets found', function (done) {
            const cache = createCacheEmpty();
            crossAccountAccess.run(cache, { s3_account_whitelist: '999999999999' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if using any whitelist', function (done) {
            const cache = createCache('2222222222222');
            crossAccountAccess.run(cache, { s3_account_whitelist: 'any' }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });
    });
});
