var expect = require('chai').expect;
var bucketUsersAclRead = require('./bucketAllUsersAclRead')

const createCacheAllUsers = (permission) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketAcl: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Grants: [{
                                Grantee: {
                                    Type: 'Group',
                                    URI: 'http://acs.amazonaws.com/groups/global/AllUsers',
                                },
                                Permission: permission,
                            }],
                        },
                    },
                },
            },
        },
    };
};

const createCacheAllAuthenticated = (permission) => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketAcl: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Grants: [{
                                Grantee: {
                                    Type: 'Group',
                                    URI: 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers',
                                },
                                Permission: permission,
                            }],
                        },
                    },
                },
            },
        },
    };
};

const createCacheSingleAccountACL = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketAcl: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            Grants: [{
                                Grantee: {
                                    Type: 'CanonicalUser',
                                    ID: 'abc123',
                                },
                                Permission: 'FULL_CONTROL',
                            }],
                        },
                    },
                },
            },
        },
    };
};

const createErrorACLCache = () => {
    return {
        s3: {
            listBuckets: {
                'us-east-1': {
                    data: [{
                        Name: 'mybucket',
                    }],
                },
            },
            getBucketAcl: {
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

describe('bucketAllUsersAclRead', function () {
    describe('run', function () {
        it('should PASS when the bucket acl does not grant world reads.', function (done) {
            const cache = createCacheAllUsers('WRITE');
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should PASS when the bucket acl does not grant world permissions.', function (done) {
            const cache = createCacheSingleAccountACL('WRITE');
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket acl does grant world reads allUsers.', function (done) {
            const cache = createCacheAllUsers('READ');
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should FAIL when the bucket acl does grant world reads allAuthenticated.', function (done) {
            const cache = createCacheAllAuthenticated('READ');
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should UNKNOWN when there was an error getting acl.', function (done) {
            const cache = createErrorACLCache();
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });

        it('should UNKNOWN when there was an error listing buckets.', function (done) {
            const cache = createErrorListBucketsCache();
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(3, 'bad status');
                done();
            });
        });

        it('should PASS when no buckets.', function (done) {
            const cache = createEmptyCache();
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should not add any results if listBuckets is null/undefined.', function (done) {
            const cache = createNullCache();
            bucketUsersAclRead.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0, 'too many results');
                done();
            });
        });
    });
});
