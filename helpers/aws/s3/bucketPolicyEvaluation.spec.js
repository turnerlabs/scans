var expect = require('chai').expect;
let bucketPolicyEvaluation = require('./bucketPolicyEvaluation')

const metadata = {}
const configEmptyCidrs = {
    s3_trusted_ip_cidrs: []
}

const configWithCidrs = {
    s3_trusted_ip_cidrs: ['48.8.24.13/32', '48.8.24.15/32', '48.9.0.0/16']
}

const sourceIpEvaluator = bucketPolicyEvaluation.CONDITIONTABLE[2].evaluator

describe('bucketPolicyEvaluation', function () {
    describe('isMitigatingCondition', function () {
        it('should return true', function (done) {
            // test1
            let condition = {
              StringEquals: {
                'aws:sourceVpc': ['vpc-abcdefg', 'vpc-123456']
              }
            }
            let allowedConditionOperators = ['StringEquals']
            let allowedConditionKeys = ['aws:sourcevpc']
            let allowedValues = ['vpc-abcdefg', 'vpc-123456']
            let allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
            let results = bucketPolicyEvaluation.isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator);
            expect(results.pass).to.equal(true);
            done();
        });
    });

    describe('sourceIpEvaluator', function () {
        it('should return false when config is empty and a cidr is supplied', function (done) {
            const cidr = '48.9.0.0/16'
            const evaluator = sourceIpEvaluator(metadata, configEmptyCidrs);
            const result = evaluator(cidr);
            expect(result).to.equal(false);
            done();
        });

        it('should return false when config is set and a cidr outside range of configs is supplied', function (done) {
            const cidr = '48.85.0.0/16'
            const evaluator = sourceIpEvaluator(metadata, configWithCidrs);
            const result = evaluator(cidr);
            expect(result).to.equal(false);
            done();
        });

        it('should return true when config is set and a cidr inside range of configs is supplied', function (done) {
            const cidr = '48.9.100.0/24'
            const evaluator = sourceIpEvaluator(metadata, configWithCidrs);
            const result = evaluator(cidr);
            expect(result).to.equal(true);
            done();
        });

        it('should return false when config is set and value that is not a cidr is supplied', function (done) {
            const cidr = 'vpc-111'
            const evaluator = sourceIpEvaluator(metadata, configWithCidrs);
            const result = evaluator(cidr);
            expect(result).to.equal(false);
            done();
        });

        it('should return false when config is not set and value that is not a cidr is supplied', function (done) {
            const cidr = 'vpc-111'
            const evaluator = sourceIpEvaluator(metadata, configEmptyCidrs);
            const result = evaluator(cidr);
            expect(result).to.equal(false);
            done();
        });
    });


    describe('isMitigatingCondition', function () {
        it('should return false when condition key is not correct', function (done) {
          // test2
          let condition = {
            StringEquals: {
              'aws:sourceVpc': ['vpc-anothervalue', 'vpc-abcdefg']
            }
          }
          let allowedConditionOperators = ['StringEquals']
          let allowedConditionKeys = ['aws:sourcevpc']
          let allowedValues = ['vpc-abcdefg', 'vpc-123456']
          let allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
          let results = bucketPolicyEvaluation.isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns false
          expect(results.pass).to.equal(false);
          done();
        });
    });
    describe('isMitigatingCondition', function () {
        it('should return true', function (done) {
            // test3
            let condition = {
              StringEquals: {
                'aws:sourceVpce': 'vpc-abcdefg'
              }
            }
            let allowedConditionOperators = ['StringEquals']
            let allowedConditionKeys = ['aws:sourcevpce']
            let allowedValues = ['vpc-abcdefg', 'vpc-123456']
            let allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
            let results = bucketPolicyEvaluation.isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns true
            expect(results.pass).to.equal(true);
            done();
        });
    });
    describe('isMitigatingCondition', function () {
        it('should return false when condition key is not correct', function (done) {
            // test4
            let condition = {
              StringEquals: {
                'aws:sourceVpc': 'vpc-abcdefg'
              }
            }
            let allowedConditionOperators = ['StringEquals']
            let allowedConditionKeys = ['aws:sourcevpce']
            let allowedValues = ['vpc-abcdefg', 'vpc-123456']
            let allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
            let results = bucketPolicyEvaluation.isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns false
            expect(results.pass).to.equal(false);
            done();
        });
    });
});
