var minimatch = require('minimatch');
const IPCIDR = require('ip-cidr');

function matchedPermissions(policyActions, permissions) {
    return permissions.filter(perm => {
        return policyActions.find(action => minimatch(perm, action));
    });
}

function hasPermissions(statement, permissions) {
    if (statement.Action) {
        var actions = typeof statement.Action === 'string' ? [statement.Action] : statement.Action;
        var grantedActions = matchedPermissions(actions, permissions);
        if (!grantedActions.length) {
            return false;
        }
    } else if (statement.NotAction) {
        var notActions = typeof statement.NotAction === 'string' ? [statement.NotAction] : statement.NotAction;
        var deniedActions = matchedPermissions(notActions, permissions);
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
        evaluator: (metadata, config) => {
            return (conditionKeyValue) => {
                if (!metadata || !metadata.describeVpcs) {
                    return false;
                }
                return metadata.describeVpcs.find(data => data.VpcId === conditionKeyValue);
            };
        }
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourcevpce'],
        evaluator: (metadata, config) => {
            return (conditionKeyValue) => {
                if (!metadata || !metadata.describeVpcEndpoints) {
                    return false;
                }
                return metadata.describeVpcEndpoints.find(data => data.VpcEndpointId === conditionKeyValue);
            };
        }
    },
    {
        operators: ['IpAddress'],
        keys: ['aws:sourceip'],
        evaluator: (metadata, config) => {
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
        evaluator: (metadata, config) => {
            return (conditionKeyValue) => {
                if (!metadata || !metadata.getCallerIdentity) {
                    return false;
                }
                if (conditionKeyValue.split(':')[4] !== metadata.getCallerIdentity) return false;
                return true;
            };
        }
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourceaccount'],
        evaluator: (metadata, config) => {
            return (conditionKeyValue) => {
                if (!metadata || !metadata.getCallerIdentity) {
                    return false;
                }
                if (conditionKeyValue !== metadata.getCallerIdentity) return false;
                return true;
            };
        }
    },
];

function evaluateConditions(statement, metadata, config) {
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
        let evaluator = definition.evaluator(metadata, config);
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

    result.failingOperatorKeyValueCombinations.push(...failingValues);  // usage of spread operator instead of Array concat because failingValues is of type Set
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

function evaluateStatement(statement, metadata, config){
    let results = {
        pass: false,
        isAllow: false,
        isDeny: false
    };
    if (!hasPermissions(statement, config.validPermissions)) {
        results.pass = true;
        return results;
    }
    if (statement.Effect && statement.Effect === 'Allow') {
        results.isAllow = true;
        if (statement.Principal) {
            if (typeof statement.Principal === 'string') {
                results.pass = statement.Principal !== '*';  // pass is false if Principal is *
            } else if (typeof statement.Principal === 'object') {
                if (statement.Principal.Service && statement.Principal.Service === '*') {
                    results.pass = false;
                } else if (statement.Principal.AWS && statement.Principal.AWS === '*') {
                    results.pass = false;
                } else if (statement.Principal.length && statement.Principal.indexOf('*') > -1) {
                    results.pass = false;
                } else {
                    results.pass = true;
                }
            }
            else {
                results.pass = true;
            }
        }
    }
    else {
        results.isDeny = true;
        results.pass = true;
    }
    return results;
}

function evaluateBucketPolicy(policy, metadata, config) {
    let results = {
        failingOperatorKeyValueCombinations: [],
        unRecognizedOperatorKeyCombinations: [],
        numberAllows: 0,
        numberDenies: 0,
        numberFailStatements: 0
    };
    for (let s in policy.Statement) {
        let statement = policy.Statement[s];
        const statementResults = evaluateStatement(statement, metadata, config);
        if (!statementResults.pass) {
            const conditionEvaluationResults = evaluateConditions(statement, metadata, config);
            conditionEvaluationResults.failingOperatorKeyValueCombinations.forEach(item => results.failingOperatorKeyValueCombinations.push(JSON.parse(item)));
            conditionEvaluationResults.unRecognizedOperatorKeyCombinations.forEach(item => results.unRecognizedOperatorKeyCombinations.push(item));
            if (!conditionEvaluationResults.pass) results.numberFailStatements += 1;
        }
        if (statementResults.isDeny) results.numberDenies += 1;
        if (statementResults.isAllow) results.numberAllows += 1;

    }
    return results;
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
    message += 'Policy summary: ' + bucketResults.numberAllows.toString() + ' allow statement(s) ' + bucketResults.numberDenies.toString() + ' deny statement(s) ' + bucketResults.numberFailStatements.toString() + ' failing statement(s)';
    return message;
}

module.exports = {
    evaluateBucketPolicy: evaluateBucketPolicy,
    isMitigatingCondition: isMitigatingCondition,
    makeBucketPolicyResultMessage: makeBucketPolicyResultMessage,
    CONDITIONTABLE: CONDITIONTABLE
};
