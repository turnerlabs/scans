var expect = require('chai').expect;
var bucketAllUsersPolicyRead = require('./bucketAllUsersPolicyRead')
var s3Permissions = require('./s3Permissions');

const createPolicy = (effect, principal, action, resource, condition, notAction) => {
    const policy = {
        Version: '2012-10-17',
        Statement: [
            {
                Effect: effect,
                Principal: principal,
                Resource: resource,
                Condition: condition,
            },
        ],
    };
    if (notAction) {
        policy.Statement[0].NotAction = action;
    } else {
        policy.Statement[0].Action = action;
    }
    return policy;
};

const createCache = (principal, action, condition, notAction) => {
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
                            Policy: JSON.stringify(createPolicy('Allow', principal, action, 'arn:aws:s3:::mybucket/*', condition, notAction)),
                        },
                    },
                },
            },
        },
    };
};


const createErrorGetBucketPolicyCache = () => {
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
                        err: {
                            message: 'some error',
                        },
                    },
                },
            },
        },
    };
};

const createErrorListBucketsCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    error: {
                        message: 'some error',
                    },
                },
            },
        },
    };
};

const createEmptyCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [],
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        s3: {},
    };
};

describe('bucketAllUsersPolicyRead', function () {
    describe('run', function () {
        it('should PASS when the bucket policy does not grant world reads.', function (done) {
            const cache = createCache('*', 's3:Put*');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants world reads.', function (done) {
            const cache = createCache('*', 's3:GetObject');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants service * reads.', function (done) {
            const cache = createCache({ Service: '*' }, 's3:GetObject');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants AWS * reads.', function (done) {
            const cache = createCache({ AWS: '*' }, 's3:GetObject');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants * reads.', function (done) {
            const cache = createCache(['*'], 's3:GetObject');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL with s3:* to the world.', function (done) {
            const cache = createCache('*', 's3:*');
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS with NotAction if it includes all read operations.', function (done) {
            const cache = createCache('*', s3Permissions.readPermissions, undefined, true);
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL with NotAction if it does not include all read operations.', function (done) {
            const cache = createCache('*', 's3:GetObject', undefined, true);
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL with NotAction if it does not include all read operations.', function (done) {
            const cache = createCache('*', 's3:GetObject', undefined, true);
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should WARN if condition is used.', function (done) {
            const cache = createCache('*', 's3:GetObject', {some: 'condition'}, true);
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(1, 'bad status');
                done();
            });
        });

        it('should not return results if listBuckets is null.', function (done) {
            const cache = createNullCache();
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0, 'too many results');
                done();
            });
        });

        it('should UNKNOWN if listBuckets errord.', function (done) {
            const cache = createErrorListBucketsCache();
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });

        it('should PASS if no buckets returned.', function (done) {
            const cache = createEmptyCache();
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });


        it('should UNKNOWN if getBucketPolicy errord.', function (done) {
            const cache = createErrorGetBucketPolicyCache();
            bucketAllUsersPolicyRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });
    });
});
