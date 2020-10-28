// allowedConditionValues (valueWithinStatement)
// right now conditionOperator isn't relevant to the allowedConditionValues function at the moment
// the allowedConditionValues function is constructed to test for a specific operator.conditionkey pairing
// for the AND case, if there is one valid operator-key-value case, then that is valid
var minimatch = require('minimatch');
const { readPermissions, writePermissions } = require('../../../plugins/aws/s3/s3Permissions');

function matchedPermissions(policyActions, permissions) {
    return permissions.filter(perm => {
        return policyActions.find(action => minimatch(perm, action));
    });
}

function noReadPermissions(statement) {
    if (statement.Action) {
        var actions = typeof statement.Action === 'string' ? [statement.Action] : statement.Action;
        var grantedReadActions = matchedPermissions(actions, readPermissions);
        if (!grantedReadActions.length) {
            return true;
        }
    } else if (statement.NotAction) {
        var notActions = typeof statement.NotAction === 'string' ? [statement.NotAction] : statement.NotAction;
        var deniedReadActions = matchedPermissions(notActions, readPermissions);
        if (deniedReadActions.length === readPermissions.length) {
            return true;
        }
    }
    return false;
}

function noWritePermissions(statement) {
    if (statement.Action) {
        var actions = typeof statement.Action === 'string' ? [statement.Action] : statement.Action;
        var grantedWriteActions = matchedPermissions(actions, writePermissions);
        if (!grantedWriteActions.length) {
            return true;
        }
    } else if (statement.NotAction) {
        var notActions = typeof statement.NotAction === 'string' ? [statement.NotAction] : statement.NotAction;
        var deniedWriteActions = matchedPermissions(notActions, writePermissions);
        if (deniedWriteActions.length === writePermissions.length) {
            return true;
        }
    }
    return false;
}


function isMitigatingCondition(statementCondition, allowedConditionOperators, allowedConditionKeys, allowedConditionValuesEvaluator) {
    let result = {
        failingValues: [],
        nonMatchingConditions: [],
        matchedConditions: [],
        pass: false
    };
    for (let [conditionOperator, parentValue] of Object.entries(statementCondition)) {
        for (let [conditionKey, conditionKeyValue] of Object.entries(parentValue)) {
            conditionKey = conditionKey.toLowerCase();
            if (typeof conditionKeyValue === 'string') conditionKeyValue = [conditionKeyValue];
            const parsedCondition = {
                conditionOperator: conditionOperator,
                conditionKey: conditionKey,
                conditionKeyValue: conditionKeyValue
            };
            let matchFound = false;
            if (allowedConditionOperators.includes(parsedCondition.conditionOperator) && allowedConditionKeys.includes(parsedCondition.conditionKey)) {
                matchFound = true;
            }
            let key;
            let isMitigating = true;
            for (key of parsedCondition.conditionKeyValue) {
                if (!allowedConditionValuesEvaluator(key)) {
                    isMitigating = false;
                    result.failingValues.push(key);
                }
            }
            if (matchFound && isMitigating) {
                result.failingValues = [];
                result.nonMatchingConditions = [];
                result.pass = true;
                return result;  // conditions are irrelevant for passing results.
            }
            if (matchFound) {
                result.matchedConditions.push(parsedCondition.conditionOperator + '.' + parsedCondition.conditionKey);
            }
            else {
                result.nonMatchingConditions.push(parsedCondition.conditionOperator + '.' + parsedCondition.conditionKey);
            }
        }
    }
    if (result.failingValues.length === 0 && result.nonMatchingConditions.length === 0) result.pass = true;
    return result;
}

function isIrrelevantStatement(statement, config) {
    if (config.mustContainRead && config.mustContainRead === true && noReadPermissions(statement)) return true;
    if (config.mustContainWrite && config.mustContainWrite === true && noWritePermissions(statement)) return true;
    return false;
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
                let data;
                let matchFound = false;
                for (data of metadata.describeVpcs) {
                    if (conditionKeyValue === data.VpcId) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
                return true;
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
                let data;
                let matchFound = false;
                for (data of metadata.describeVpcEndpoints) {
                    if (conditionKeyValue === data.VpcEndpointId) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
                return true;
            };
        }
    },
    {
        operators: ['IpAddress'],
        keys: ['aws:sourceip'],
        evaluator: (metadata, config) => {
            return (conditionKeyValue) => {
                if (!config || !config.s3_trusted_ip_cidrs) {
                    return false;
                }
                let data;
                let matchFound = false;
                for (data of config.s3_trusted_ip_cidrs) {
                    if (conditionKeyValue === data) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
                return true;
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

function getSpecificTag(metadata, config) {
    if (metadata.getBucketTagging && metadata.getBucketTagging.TagSet) {
        let tag;
        for (tag of metadata.getBucketTagging.TagSet) {
            if (config.s3_public_tags === tag.Key) {
                return tag.Key.concat(':', tag.Value);
            }
        }
    }
    return '';
}

function evaluateConditions(statement, metadata, config) {
    // assumes there are conditions
    // checks to see if one of the conditions is mitigating
    let result = {
        pass: false,
        conditions: [],
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
            return result;
        }
        mitigatingConditionResults.nonMatchingConditions.forEach(item => nonMatchingConditions.add(item));
        mitigatingConditionResults.failingValues.forEach(item => failingValues.add(item));
        mitigatingConditionResults.matchedConditions.forEach(item => matchedConditions.add(item));
    }

    result.conditions.push(...failingValues);
    let condition;
    for (condition of nonMatchingConditions) {
        // If the condition key is one of the condition keys present in the above table the failing value should be included in the message.
        // If the condition key is not one of the condition keys present in the above table the failing value should include the condition-operator and condition-key pair. e.g. StringEquals.aws:UserAgent
        // if key is present in table, avoid including it in the results as being not-in-the-table as well.
        if (!matchedConditions.has(condition)) result.conditions.push(condition);
    }
    return result;
}

function evaluateStatement(statement, metadata, config){
    let results = {
        pass: false,
        conditions: [],
        isAllow: false,
        isDeny: false
    };
    if (isIrrelevantStatement(statement, config)) {
        results.pass = true;
        return results;
    }
    if (statement.Effect && statement.Effect === 'Allow') {
        results.isAllow = true;
        if (statement.Principal) {
            let starPrincipal = false;
            if (typeof statement.Principal === 'string') {
                if (statement.Principal === '*') {
                    starPrincipal = true;
                }
            } else if (typeof statement.Principal === 'object') {
                if (statement.Principal.Service && statement.Principal.Service === '*') {
                    starPrincipal = true;
                } else if (statement.Principal.AWS && statement.Principal.AWS === '*') {
                    starPrincipal = true;
                } else if (statement.Principal.length && statement.Principal.indexOf('*') > -1) {
                    starPrincipal = true;
                }
            }
            if (starPrincipal && statement.Condition) {
                let conditionResults = evaluateConditions(statement, metadata, config);
                results.pass = conditionResults.pass;
                if (conditionResults.conditions) results.conditions.push(...conditionResults.conditions);
            }
            else {
                results.pass = !starPrincipal;
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
        nonPassingConditions: new Set(),  // either failing value or operator.key pair.
        numberAllows: 0,
        numberDenies: 0,
        numberFailStatements: 0,
        tag: getSpecificTag(metadata, config)
    };
    for (let s in policy.Statement) {
        let statement = policy.Statement[s];
        const statementResults = evaluateStatement(statement, metadata, config);
        if (statementResults.isDeny) results.numberDenies += 1;
        if (statementResults.isAllow) results.numberAllows += 1;
        if (!statementResults.pass) {
            statementResults.conditions.forEach(item => results.nonPassingConditions.add(item));
            results.numberFailStatements += 1;
        }
    }
    results.nonPassingConditions = [...results.nonPassingConditions];
    return results;
}
module.exports = {
    evaluateBucketPolicy: evaluateBucketPolicy,
    isMitigatingCondition: isMitigatingCondition
};
