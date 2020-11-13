var expect = require('chai').expect;
const openAllPortsProtocols = require('./openAllPortsProtocols');

const securityGroups = [
          {
            "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
            "GroupName": "launch-wizard-1",
            "IpPermissions": [
              {
                "FromPort": 22,
                "IpProtocol": "tcp",
                "IpRanges": [
                  {
                    "CidrIp": "0.0.0.0/0"
                  }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 22,
                "UserIdGroupPairs": []
              }
            ],
            "OwnerId": "560213429563",
            "GroupId": "sg-0ff1642cae23c309a",
            "IpPermissionsEgress": [],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "launch-wizard-1 created 2020-08-10T14:28:09.271+05:00",
            "GroupName": "launch-wizard-1",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "-1",
                "IpRanges": [
                  {
                    "CidrIp": "0.0.0.0/0"
                  }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": []
              }
            ],
            "OwnerId": "560213429563",
            "GroupId": "sg-0ff1642cae23c309a",
            "IpPermissionsEgress": [],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "ESP 50",
            "GroupName": "spec-test-sg",
            "OwnerId": "560213429563",
            "GroupId": "sg-0b5f2771716acfee4",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "50",
                "IpRanges": [
                  {
                    "CidrIp": "0.0.0.0/0"
                  }
                ],
                "Ipv6Ranges": [
                  {
                    "CidrIpv6": "::/0"
                  }
                ],
                "PrefixListIds": [],
                "ToPort": 0,
                "UserIdGroupPairs": []
              }
            ],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "AH 51",
            "GroupName": "spec-test-sg",
            "OwnerId": "560213429563",
            "GroupId": "sg-0b5f2771716acfee4",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "51",
                "IpRanges": [
                  {
                    "CidrIp": "0.0.0.0/0"
                  }
                ],
                "Ipv6Ranges": [
                  {
                    "CidrIpv6": "::/0"
                  }
                ],
                "PrefixListIds": [],
                "ToPort": 0,
                "UserIdGroupPairs": []
              }
            ],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "ESP 50 not open to world",
            "GroupName": "spec-test-sg",
            "OwnerId": "560213429563",
            "GroupId": "sg-0b5f2771716acfee4",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "50",
                "IpRanges": [
                  {
                    "CidrIp": "5.5.5.5/24"
                  }
                ],
                "Ipv6Ranges": [
                  {
                    "CidrIpv6": "2001:db8::1234/32"
                  }
                ],
                "PrefixListIds": [],
                "ToPort": 0,
                "UserIdGroupPairs": []
              }
            ],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "AH 51 not open to world",
            "GroupName": "spec-test-sg",
            "OwnerId": "560213429563",
            "GroupId": "sg-0b5f2771716acfee4",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "51",
                "IpRanges": [
                  {
                    "CidrIp": "5.5.5.5/24"
                  }
                ],
                "Ipv6Ranges": [
                  {
                    "CidrIpv6": "2001:db8::1234/32"
                  }
                ],
                "PrefixListIds": [],
                "ToPort": 0,
                "UserIdGroupPairs": []
              }
            ],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          },
          {
            "Description": "tcp all ports open",
            "GroupName": "launch-wizard-1",
            "IpPermissions": [
              {
                "FromPort": 0,
                "IpProtocol": "tcp",
                "IpRanges": [
                  {
                    "CidrIp": "0.0.0.0/0"
                  }
                ],
                "Ipv6Ranges": [],
                "PrefixListIds": [],
                "ToPort": 65535,
                "UserIdGroupPairs": []
              }
            ],
            "OwnerId": "560213429563",
            "GroupId": "sg-0ff1642cae23c309a",
            "IpPermissionsEgress": [],
            "Tags": [],
            "VpcId": "vpc-99de2fe4"
          }
        ];

const createCache = (securityGroups) => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    data: securityGroups
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': {
                    err: {
                        message: 'error describing security groups'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        ec2: {
            describeSecurityGroups: {
                'us-east-1': null,
            },
        },
    };
};

describe('openAllPortsProtocols', function () {
    describe('run', function () {
        it('should PASS if security groups do not involve all-ports-all-protocols', function (done) {
            const cache = createCache([securityGroups[0]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if security groups are all-ports-all-protocols', function (done) {
            const cache = createCache([securityGroups[1]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('all protocols');
                done();
            });
        });

        it('should FAIL when protocol 50 is open to world', function (done) {
            const cache = createCache([securityGroups[2]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('protocol ');
                expect(results[0].message).to.include('::/0');
                expect(results[0].message).to.include('0.0.0.0/0');
                done();
            });
        });

        it('should FAIL when protocol 51 is open to world', function (done) {
            const cache = createCache([securityGroups[3]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('protocol ');
                expect(results[0].message).to.include('::/0');
                expect(results[0].message).to.include('0.0.0.0/0');
                done();
            });
        });

        it('should PASS when protocol 50 is not open to world', function (done) {
            const cache = createCache([securityGroups[4]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS when protocol 51 is not open to world', function (done) {
            const cache = createCache([securityGroups[5]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error describing security groups', function (done) {
            const cache = createErrorCache();
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for security groups', function (done) {
            const cache = createNullCache();
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should FAIL if security groups tcp is all-ports-open', function (done) {
            const cache = createCache([securityGroups[6]]);
            openAllPortsProtocols.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('tcp all ports open');
                done();
            });
        });
    });
});
