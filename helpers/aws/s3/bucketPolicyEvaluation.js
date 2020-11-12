const minimatch = require('minimatch');
const IPCIDR = require('ip-cidr');

function matchedPermissions(policyActions, permissions) {
    return permissions.filter(perm => {
        return policyActions.find(action => minimatch(perm, action));
    });
}

function hasPermissions(statement, permissions) {
    if (statement.Action) {
        let actions = typeof statement.Action === 'string' ? [statement.Action] : statement.Action;
        let grantedActions = matchedPermissions(actions, permissions);
        if (!grantedActions.length) {
            return false;
        }
    } else if (statement.NotAction) {
        let notActions = typeof statement.NotAction === 'string' ? [statement.NotAction] : statement.NotAction;
        let deniedActions = matchedPermissions(notActions, permissions);
        if (deniedActions.length === permissions.length) {
            return false;
        }
    }
    return true;
}


function isMitigatingCondition(statementCondition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) {
    let result = {
        failingValues: [],
        nonMatchingConditions: [],
        matchedConditions: [],
        pass: false
    };
    if (statementCondition === null || statementCondition === undefined) return result;  // handle case in which there was no condition
    for (let [conditionOperator, parentValue] of Object.entries(statementCondition)) {
        for (let [conditionKey, conditionKeyValue] of Object.entries(parentValue)) {
            conditionKey = conditionKey.toLowerCase();
            if (typeof conditionKeyValue === 'string') conditionKeyValue = [conditionKeyValue];
            const matchFound = allowedConditionOperators.includes(conditionOperator) && allowedConditionKeys.includes(conditionKey);
            if (matchFound) {
                result.failingValues = conditionKeyValue.filter((value) => !allowedConditionValuesEvaluator(value)).map(
                    badValue => ({conditionOperator: conditionOperator, conditionKey: conditionKey, offendingValue: badValue})
                );
            }
            if (matchFound && result.failingValues.length === 0) {
                result.failingValues = [];
                result.nonMatchingConditions = [];
                result.pass = true;
                return result;  // conditions are irrelevant for passing results.
            }
            if (matchFound) {
                result.matchedConditions.push(conditionOperator + '.' + conditionKey.toString());
            }
            else {
                result.nonMatchingConditions.push(conditionOperator + '.' + conditionKey.toString());
            }
        }
    }
    if (result.failingValues.length === 0 && result.nonMatchingConditions.length === 0) result.pass = true;
    return result;
}


const CONDITIONTABLE = [
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourcevpc'],
        evaluator: (config) => {
            return (conditionKeyValue) => {
                if (!config.metadata || !config.metadata.describeVpcs) {
                    return false;
                }
                return config.metadata.describeVpcs.find(data => data.VpcId === conditionKeyValue);
            };
        }
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourcevpce'],
        evaluator: (config) => {
            return (conditionKeyValue) => {
                if (!config.metadata || !config.metadata.describeVpcEndpoints) {
                    return false;
                }
                return config.metadata.describeVpcEndpoints.find(data => data.VpcEndpointId === conditionKeyValue);
            };
        }
    },
    {
        operators: ['IpAddress'],
        keys: ['aws:sourceip'],
        evaluator: (config) => {
            return (conditionKeyValue) => {
                if (!config || !config.s3_trusted_ip_cidrs || config.s3_trusted_ip_cidrs.length === 0) {
                    return false;
                }
                let cidrToEval;
                if (conditionKeyValue.includes('/') || conditionKeyValue.includes(':')) {
                    // ':' is to check for ipv6 and not add a mask to it.
                    cidrToEval = new IPCIDR(conditionKeyValue);
                }
                else {
                    // if somehow the subnet mask is omitted, use /32.
                    cidrToEval = new IPCIDR(conditionKeyValue + '/32');
                }
                try {
                    cidrToEval = cidrToEval.toRange();  // convert cidr into range of ip addresses.
                } catch (error) {
                    if (error.constructor === TypeError) return false;  // conditionKeyValue is not a valid cidr
                    else throw error;
                }
                return config.s3_trusted_ip_cidrs.some(
                    (trustedCidr) => {
                        trustedCidr = new IPCIDR(trustedCidr);
                        let addressMatchesTrustedRange = false;
                        for (const addressToEval of cidrToEval) {
                            if (!trustedCidr.contains(addressToEval)) {
                                addressMatchesTrustedRange = false;
                                break;
                            }
                            addressMatchesTrustedRange = true;
                        }
                        return addressMatchesTrustedRange;
                    }
                );
            };
        }
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase', 'ArnEquals', 'ArnLike'],
        keys: ['aws:sourcearn'],
        evaluator: (config) => {
            // config.metadata.account can be a string or array of string
            return (conditionKeyValue) => {
                if (!config.metadata || !config.metadata.account) {
                    return false;
                }
                let accountIds = [];
                if (typeof config.metadata.account === 'string') {
                    accountIds.push(config.metadata.account);
                }
                else {
                    // assuming 'account' is array
                    accountIds = config.metadata.account;
                }
                return accountIds.includes(conditionKeyValue.split(':')[4]);
            };
        }
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourceaccount'],
        evaluator: (config) => {
            // config.metadata.account can be a string or array of string
            return (conditionKeyValue) => {
                if (!config.metadata || !config.metadata.account) {
                    return false;
                }
                let accountIds = [];
                if (typeof config.metadata.account === 'string') {
                    accountIds.push(config.metadata.account);
                }
                else {
                    // assuming 'account' is array
                    accountIds = config.metadata.account;
                }
                return accountIds.includes(conditionKeyValue);
            };
        }
    },
];

function evaluateConditions(statement, config) {
    // checks to see if one of the conditions is mitigating
    let result = {
        pass: false,
        failingOperatorKeyValueCombinations: [],
        unRecognizedOperatorKeyCombinations: []
    };
    let definition;
    let mitigatingConditionResults;
    let failingValues = new Set();
    let nonMatchingConditions = new Set();
    let matchedConditions = new Set();
    for (definition of CONDITIONTABLE) {
        let evaluator = definition.evaluator(config);
        mitigatingConditionResults = isMitigatingCondition(statement.Condition, definition.operators, definition.keys, evaluator);
        if (mitigatingConditionResults.pass === true) {
            result.pass = true;
            result.failingOperatorKeyValueCombinations = []; // irrelevant in this case
            result.unRecognizedOperatorKeyCombinations = []; // irrelevant in this case
            return result;
        }
        mitigatingConditionResults.nonMatchingConditions.forEach(item => nonMatchingConditions.add(item));
        mitigatingConditionResults.failingValues.forEach(item => failingValues.add(JSON.stringify(item)));   // stringify this because sets don't work with objects like I would expect.
        mitigatingConditionResults.matchedConditions.forEach(item => matchedConditions.add(item));
    }
    failingValues.forEach((element) => result.failingOperatorKeyValueCombinations.push(JSON.parse(element)));
    let condition;
    if (result.failingOperatorKeyValueCombinations.length === 0){
        // unRecognized combos are only relevant if failing operator length is 0
        for (condition of nonMatchingConditions) {
            // nonMatchingConditions will contain almost every condition passed into function evaluateConditions
            // therefore, we check nonMatchingConditions against matchedConditions to get the set difference
            if (!matchedConditions.has(condition)) result.unRecognizedOperatorKeyCombinations.push(condition);
        }
    }
    return result;
}

function doesStatementAllowPublicAccessForPermissions(statement, permissions){
    if (!hasPermissions(statement, permissions)) {
        return false;
    }
    if (statement.Effect && statement.Effect === 'Allow') {
        if (statement.Principal) {
            if (typeof statement.Principal === 'string') {
                return statement.Principal === '*';
            } else if (typeof statement.Principal === 'object') {
                if (statement.Principal.Service && statement.Principal.Service === '*') {
                    return true;
                } else if (statement.Principal.AWS && statement.Principal.AWS === '*') {
                    return true;
                } else if (statement.Principal.length && statement.Principal.indexOf('*') > -1) {
                    return true;
                }
            }
        }
    }
    return false;
}

function makeBucketPolicyResultMessage(bucketResults) {
    let message = '';
    if (bucketResults.failingOperatorKeyValueCombinations && bucketResults.failingOperatorKeyValueCombinations.length !== 0) {
        message += 'The policy has statements that make the bucket public with mitigating conditions with not allowed values: ';
        let failedCombo;
        let failedCombos = {};
        for (failedCombo of bucketResults.failingOperatorKeyValueCombinations) {
            let comboKey = failedCombo.conditionOperator.toString() + '.' + failedCombo.conditionKey.toString();
            let failedValue = failedCombo.offendingValue.toString();
            if (comboKey in failedCombos) {
                failedCombos[comboKey].push(failedValue);
            }
            else {
                failedCombos[comboKey] = [failedValue];
            }
        }
        let aggregatedCombos = [];
        for (const [key, value] of Object.entries(failedCombos)) {
            let tempMessage = key;
            tempMessage += ' allows ';
            tempMessage += value.join(', ');
            aggregatedCombos.push(tempMessage);
        }
        message += aggregatedCombos.join('; ');
        message += '\n';
    }
    if (bucketResults.unRecognizedOperatorKeyCombinations && bucketResults.unRecognizedOperatorKeyCombinations.length !== 0) {
        message += 'The policy has statements that make the bucket public with the following non-mitigating conditions: ';
        let unRecognizedCombo;
        let unRecognizedCombos = [];
        for (unRecognizedCombo of bucketResults.unRecognizedOperatorKeyCombinations) {
            unRecognizedCombos.push(unRecognizedCombo);
        }
        message += unRecognizedCombos.join(', ');
        message += '\n';
    }
    return message;
}

function addNumberAllowsDeniesFailsMessage(message, numberAllows, numberDenies, numFail) {
    return message + 'Policy summary: ' + numberAllows + ' allow statement(s) ' + numberDenies + ' deny statement(s) ' + numFail + ' failing statement(s)';
}

module.exports = {
    isMitigatingCondition: isMitigatingCondition,
    makeBucketPolicyResultMessage: makeBucketPolicyResultMessage,
    CONDITIONTABLE: CONDITIONTABLE,
    doesStatementAllowPublicAccessForPermissions: doesStatementAllowPublicAccessForPermissions,
    evaluateConditions: evaluateConditions,
    addNumberAllowsDeniesFailsMessage: addNumberAllowsDeniesFailsMessage
};
