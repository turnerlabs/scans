var expect = require('chai').expect;
var bucketAllUsersPolicyWrite = require('./bucketAllUsersPolicyWrite')
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

describe('bucketAllUsersPolicyWrite', function () {
    describe('run', function () {
        it('should PASS when the bucket policy does not grant world writes.', function (done) {
            const cache = createCache('*', 's3:Get*');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants world writes.', function (done) {
            const cache = createCache('*', 's3:PutObject');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants service * writes.', function (done) {
            const cache = createCache({ Service: '*' }, 's3:PutObject');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants AWS * writes.', function (done) {
            const cache = createCache({ AWS: '*' }, 's3:PutObject');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket policy grants * writes.', function (done) {
            const cache = createCache(['*'], 's3:PutObject');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL with s3:* to the world.', function (done) {
            const cache = createCache('*', 's3:*');
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS with NotAction if it includes all write operations.', function (done) {
            const cache = createCache('*', s3Permissions.writePermissions, undefined, true);
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL with NotAction if it does not include all write operations.', function (done) {
            const cache = createCache('*', 's3:PutObject', undefined, true);
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL with NotAction if it does not include all write operations.', function (done) {
            const cache = createCache('*', 's3:PutObject', undefined, true);
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should WARN if condition is used.', function (done) {
            const cache = createCache('*', 's3:PutObject', {some: 'condition'}, true);
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(1, 'bad status');
                done();
            });
        });

        it('should not return results if listBuckets is null.', function (done) {
            const cache = createNullCache();
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0, 'too many results');
                done();
            });
        });

        it('should UNKNOWN if listBuckets errord.', function (done) {
            const cache = createErrorListBucketsCache();
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });

        it('should PASS if no buckets returned.', function (done) {
            const cache = createEmptyCache();
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });


        it('should UNKNOWN if getBucketPolicy errord.', function (done) {
            const cache = createErrorGetBucketPolicyCache();
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'too many results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });
    });
});
