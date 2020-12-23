var expect = require('chai').expect;
var snsTopicPolicies = require('./topicPolicies');

const createCache = (policy) => {
    const arn = 'arn:aws:sns:us-west-2:000000000000:aaaaaaaaaaaa'
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: [
                        {
                            "TopicArn": arn
                        }
                    ]
                }
            },
            getTopicAttributes: {
                'us-east-1': {
                    [arn]: {
                        data: {
                            Attributes: {
                                Policy: JSON.stringify(policy)
                            }
                        }
                    }
                }
            }
        }
    }
};

const createErrorCache = (message) => {
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    err: {
                        message: message
                    }
                }
            },
            getTopicAttributes: {
                'us-east-1': {
                    err: {
                        message: message
                    }
                }
            }
        }
    }
};

const createNoTopicsCache = () => {
    return {
        sns: {
            listTopics: {
                'us-east-1': {
                    data: []
                }
            },
            getTopicAttributes: {}
        }
    }
};

describe('topicPolicies', function () {
    describe('run', function () {
        it('should PASS if allow, open principal, but SourceOwner does not include "*"', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not allow global')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceOwner: '111111111111'
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should PASS if allow, open principal, but SourceArn does not contain "*"', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not allow global')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceArn: '111111111111'
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should FAIL if allow, open principal, but SourceOwner contains "*"', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceOwner: '*'
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })
        it('should FAIL if allow, open principal, but SourceOwner contains "*" (array)', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceOwner: ['*']
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should FAIL if allow, open principal, but SourceArn contains "*"', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceArn: '*'
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should FAIL if allow, open principal, but SourceArn contains "*" (array)', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*",
                            Condition: {
                                SourceArn: ['*']
                            }
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should FAIL if allow, open principal (string), and there is no condition set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: "*"
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*"
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should FAIL if allow, open principal (array), and there is no condition set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('allows global access')
                done()
            };

            const cache = createCache(
                {
                    Statement: [
                        {
                            Effect: 'Allow',
                            Principal: {
                                AWS: ["*"]
                            },
                            Action: [
                                "sns:GetTopicAttributes"
                            ],
                            Resource: "*"
                        }
                    ]
                }
            );

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should UNKNOWN if both calls errored', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query')
                done()
            };

            const cache = createErrorCache('foo');

            snsTopicPolicies.run(cache, {}, callback);
        })

        it('should PASS if there are no SNS topics', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No SNS topics')
                done()
            };

            const cache = createNoTopicsCache();

            snsTopicPolicies.run(cache, {}, callback);
        })

    });
})
