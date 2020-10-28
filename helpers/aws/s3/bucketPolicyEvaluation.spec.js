// test1
condition = {
  StringEquals: {
    'aws:sourceVpc': ['vpc-abcdefg', 'vpc-123456']
  }
}
allowedConditionOperators = ['StringEquals']
allowedConditionKeys = ['aws:sourcevpc']
allowedValues = ['vpc-abcdefg', 'vpc-123456']
allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns true
// test2
condition = {
  StringEquals: {
    'aws:sourceVpc': ['vpc-anothervalue', 'vpc-abcdefg']
  }
}
allowedConditionOperators = ['StringEquals']
allowedConditionKeys = ['aws:sourcevpc']
allowedValues = ['vpc-abcdefg', 'vpc-123456']
allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
function isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns false
// test3
condition = {
  StringEquals: {
    'aws:sourceVpce': 'vpc-abcdefg'
  }
}
allowedConditionOperators = ['StringEquals']
allowedConditionKeys = ['aws:sourcevpce']
allowedValues = ['vpc-abcdefg', 'vpc-123456']
allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
function isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns true
// test4
condition = {
  StringEquals: {
    'aws:sourceVpc': 'vpc-abcdefg'
  }
}
allowedConditionOperators = ['StringEquals']
allowedConditionKeys = ['aws:sourcevpce']
allowedValues = ['vpc-abcdefg', 'vpc-123456']
allowedConditionValuesEvaluator = (vpc) => allowedValues.includes(vpc)
function isMitigatingCondition(condition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) // returns false
