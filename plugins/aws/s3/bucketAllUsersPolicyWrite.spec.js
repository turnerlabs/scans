var expect = require('chai').expect;
var bucketAllUsersPolicyWrite = require('./bucketAllUsersPolicyWrite')
var s3Permissions = require('./s3Permissions');

const VPCE = 'vpce-11111111111111';
const VPC = 'vpc-eeeeeeeeeeeeee'
const MYKEY = 'myKey';
const MYVALUE = 'myValue';
const OWNER = '22222222222';
const MYIPS = ['48.8.24.13/32', '48.8.24.15/32', '48.9.0.0/16']
const MYARN = 'arn:aws:lambda:us-east-1:22222222222:function:BizBaz-prod';

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
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    data: [
                        {
                            "VpcEndpointId": VPCE,
                            "VpcEndpointType": "Gateway",
                            "VpcId": "vpc-1111111111",
                            "ServiceName": "com.amazonaws.us-east-1.s3",
                            "State": "available",
                            "PolicyDocument": "{}",
                            "RouteTableIds": [],
                            "SubnetIds": [],
                            "Groups": [],
                            "PrivateDnsEnabled": false,
                            "RequesterManaged": false,
                            "NetworkInterfaceIds": [],
                            "DnsEntries": [],
                            "CreationTimestamp": "2019-10-12T21:13:16.000Z",
                            "Tags": [],
                            "OwnerId": OWNER
                        }
                    ]
                },
                'us-east-2': {
                    data: [
                        {
                            "VpcEndpointId": 'vpce-11111111111112',
                            "VpcEndpointType": "Gateway",
                            "VpcId": "vpc-1111111112",
                            "ServiceName": "com.amazonaws.us-east-1.s3",
                            "State": "available",
                            "PolicyDocument": "{}",
                            "RouteTableIds": [],
                            "SubnetIds": [],
                            "Groups": [],
                            "PrivateDnsEnabled": false,
                            "RequesterManaged": false,
                            "NetworkInterfaceIds": [],
                            "DnsEntries": [],
                            "CreationTimestamp": "2019-10-12T21:13:16.000Z",
                            "Tags": [],
                            "OwnerId": OWNER
                        }
                    ]
                }
            },
            describeVpcs: {
                'us-east-1': {
                    data: [
                        {
                            "CidrBlock": "172.16.0.0/16",
                            "DhcpOptionsId": "dopt-ea3t43n",
                            "State": "available",
                            "VpcId": VPC,
                            "OwnerId": OWNER,
                            "InstanceTenancy": "default",
                            "Ipv6CidrBlockAssociationSet": [],
                            "CidrBlockAssociationSet": [
                              {
                                "AssociationId": "vpc-cidr-assoc-3euaeou3au3",
                                "CidrBlock": "172.16.0.0/16",
                                "CidrBlockState": {
                                  "State": "associated"
                                }
                              }
                            ],
                            "IsDefault": false,
                            "Tags": []
                        }
                    ]
                }
            },
        },
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
            getBucketTagging: {
                'us-east-1': {
                    mybucket: {
                        data: {
                            TagSet: [
                                {
                                    Key: MYKEY,
                                    Value: MYVALUE
                                },
                            ]
                        },
                    },
                },
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: OWNER
                }
            }
        }
    };
};


const createErrorGetBucketPolicyCache = () => {
    return {
        ec2: {
            describeVpcEndpoints: {
                'us-east-1': {
                    data: [
                        {
                            "VpcEndpointId": VPCE,
                            "VpcEndpointType": "Gateway",
                            "VpcId": "vpc-1111111111",
                            "ServiceName": "com.amazonaws.us-east-1.s3",
                            "State": "available",
                            "PolicyDocument": "{}",
                            "RouteTableIds": [],
                            "SubnetIds": [],
                            "Groups": [],
                            "PrivateDnsEnabled": false,
                            "RequesterManaged": false,
                            "NetworkInterfaceIds": [],
                            "DnsEntries": [],
                            "CreationTimestamp": "2019-10-12T21:13:16.000Z",
                            "Tags": [],
                            "OwnerId": OWNER
                        }
                    ]
                }
            },
            describeVpcs: {
                'us-east-1': {
                    data: [
                        {
                            "CidrBlock": "172.16.0.0/16",
                            "DhcpOptionsId": "dopt-ea3t43n",
                            "State": "available",
                            "VpcId": VPC,
                            "OwnerId": OWNER,
                            "InstanceTenancy": "default",
                            "Ipv6CidrBlockAssociationSet": [],
                            "CidrBlockAssociationSet": [
                              {
                                "AssociationId": "vpc-cidr-assoc-3euaeou3au3",
                                "CidrBlock": "172.16.0.0/16",
                                "CidrBlockState": {
                                  "State": "associated"
                                }
                              }
                            ],
                            "IsDefault": false,
                            "Tags": []
                        }
                    ]
                }
            },
        },
        sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: OWNER
                }
            }
        },
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
                    err: {
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

        it('should return tagging info on failures', function (done) {
            const cache = createCache(['*'], 's3:PutObject');
            bucketAllUsersPolicyWrite.run(cache, {s3_public_tags: MYKEY}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                expect(results[0].message.includes(MYVALUE));
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

        it('should PASS if non-mitigating condition is used with a mitigating condition (SourceVpc)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {
                        'aws:SourceVpc': 'vpc-oeuaaeo',
                        'aws:SourceVpce': VPCE
                }},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if non-mitigating condition is used (SourceVpc)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceVpc': 'vpc-oeuaaeo'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceVpc)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceVpc': VPC}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if non-mitigating condition is used (SourceVpce)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceVpce': 'vpce-oeuaaeo'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceVpce)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceVpce': VPCE}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used with vcpe in another region (SourceVpce)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceVpce': 'vpce-11111111111112'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if non-mitigating condition is used (SourceIp)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceIp)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'IpAddress': {'aws:SourceIp': MYIPS}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {s3_trusted_ip_cidrs: MYIPS}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceIp) (ip address is within trusted range)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'IpAddress': {'aws:SourceIp': '48.9.25.122'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {s3_trusted_ip_cidrs: MYIPS}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceIp) (ip range is within trusted range)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'IpAddress': {'aws:SourceIp': '48.9.25.0/24'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {s3_trusted_ip_cidrs: MYIPS}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if non-mitigating condition is used (SourceArn)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'ArnEquals': {'aws:SourceArn': 'arn:aws:lambda:us-east-1:333333333333:function:OtherThing-prod'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceArn)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'ArnEquals': {'aws:SourceArn': MYARN}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if non-mitigating condition is used (SourceAccount)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceAccount': '999999999999'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
                done();
            });
        });

        it('should PASS if mitigating condition is used (SourceAccount)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:SourceAccount': OWNER}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(0, 'bad status');
                done();
            });
        });

        it('should FAIL if unRecognized condition is used (UserAgent)', function (done) {
            const cache = createCache(
                '*', 's3:PutObject',
                {'StringEquals': {'aws:UserAgent': 'uaeo'}},
                true
            );
            bucketAllUsersPolicyWrite.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1, 'not enough results');
                expect(results[0].status).to.equal(2, 'bad status');
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
