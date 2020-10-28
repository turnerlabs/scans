var expect = require('chai').expect;
let bucketPolicyEvaluation = require('./bucketPolicyEvaluation')

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
        });
    });
});
