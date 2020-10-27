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
        pass: false,
        conditions: []
    };
    for (let [conditionOperator, parentValue] of Object.entries(statementCondition)) {
        for (let [conditionKey, conditionKeyValue] of Object.entries(parentValue)) {
            conditionKey = conditionKey.toLowerCase();
            const parsedCondition = {
                conditionOperator: conditionOperator,
                conditionKey: conditionKey,
                conditionKeyValue: conditionKeyValue
            };
            let foundInTable = false;
            if (allowedConditionOperators.includes(parsedCondition.conditionOperator) && allowedConditionKeys.includes(parsedCondition.conditionKey)) {
                foundInTable = true;
            }
            if (foundInTable && allowedConditionValuesEvaluator(parsedCondition)) {
                result.pass = true;
                result.conditions = [];
                return result;  // conditions are irrelevant for passing results.
            }
            if (foundInTable) result.conditions.push(parsedCondition.conditionKeyValue);
            else result.conditions.push(parsedCondition.conditionOperator + '.' + parsedCondition.conditionKey);
        }
    }
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
        keys: ['aws:sourcevpc']
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourcevpce']
    },
    {
        operators: ['IpAddress'],
        keys: ['aws:sourceip']
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase', 'ArnEquals', 'ArnLike'],
        keys: ['aws:sourcearn']
    },
    {
        operators: ['StringEquals', 'StringEqualsIgnoreCase'],
        keys: ['aws:sourceaccount']
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

function makeAllowedConditionValuesEvaluator(metadata, config) {
    return (statementCondition) => {
        let conditionKeyValue = statementCondition.conditionKeyValue;
        if (['StringEquals', 'StringEqualsIgnoreCase'].includes(statementCondition.conditionOperator) && ['aws:sourcevpc'].includes(statementCondition.conditionKey)) {
            if (!metadata || !metadata.describeVpcs) {
                return false;
            }
            if (typeof conditionKeyValue === 'string') {
                conditionKeyValue = [conditionKeyValue];
            }
            let key;
            let data;
            for (key of conditionKeyValue){
                let matchFound = false;
                for (data of metadata.describeVpcs) {
                    if (key === data.VpcId) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
            }
            return true;
        }
        else if (['StringEquals', 'StringEqualsIgnoreCase'].includes(statementCondition.conditionOperator) && ['aws:sourcevpce'].includes(statementCondition.conditionKey)) {
            if (!metadata || !metadata.describeVpcEndpoints) {
                return false;
            }
            if (typeof conditionKeyValue === 'string') {
                conditionKeyValue = [conditionKeyValue];
            }
            let key;
            let data;
            for (key of conditionKeyValue){
                let matchFound = false;
                for (data of metadata.describeVpcEndpoints) {
                    if (key === data.VpcEndpointId) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
            }
            return true;
        }
        else if (['IpAddress'].includes(statementCondition.conditionOperator) && ['aws:sourceip'].includes(statementCondition.conditionKey)) {
            if (!config || !config.s3_trusted_ip_cidrs) {
                return false;
            }
            if (typeof conditionKeyValue === 'string') {
                conditionKeyValue = [conditionKeyValue];
            }
            let key;
            let data;
            for (key of conditionKeyValue){
                let matchFound = false;
                for (data of config.s3_trusted_ip_cidrs) {
                    if (key === data) {
                        matchFound = true;
                        break;
                    }
                }
                if (!matchFound) return false;
            }
            return true;
        }
        else if (['StringEquals', 'StringEqualsIgnoreCase', 'ArnEquals', 'ArnLike'].includes(statementCondition.conditionOperator) && ['aws:sourcearn'].includes(statementCondition.conditionKey)) {
            if (!metadata || !metadata.getCallerIdentity) {
                return false;
            }
            if (typeof conditionKeyValue === 'string') {
                conditionKeyValue = [conditionKeyValue];
            }
            let key;
            for (key of conditionKeyValue){
                if (key.split(':')[4] !== metadata.getCallerIdentity) return false;
            }
            return true;
        }
        else if (['StringEquals', 'StringEqualsIgnoreCase'].includes(statementCondition.conditionOperator) && ['aws:sourceaccount'].includes(statementCondition.conditionKey)) {
            if (!metadata || !metadata.getCallerIdentity) {
                return false;
            }
            if (typeof conditionKeyValue === 'string') {
                conditionKeyValue = [conditionKeyValue];
            }
            let key;
            for (key of conditionKeyValue){
                if (key !== metadata.getCallerIdentity) return false;
            }
            return true;
        }
        return false;
    };
}

function evaluateConditions(statement, metadata, config) {
    // assumes there are conditions
    // checks to see if one of the conditions is mitigating
    let definition;
    let allowedConditionOperators = [];
    let allowedConditionKeys = [];
    let evaluator = makeAllowedConditionValuesEvaluator(metadata, config);
    for (definition of CONDITIONTABLE) {
        allowedConditionOperators.push(...definition.operators);
        allowedConditionKeys.push(...definition.keys);
    }
    return isMitigatingCondition(statement.Condition, allowedConditionOperators, allowedConditionKeys, evaluator);
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
                if (conditionResults.pass === true) {
                    results.pass = true;
                }
                else {
                    results.conditions.push(...conditionResults.conditions);
                }
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
        nonPassingConditions: [],  // either failing value or operator.key pair.
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
            results.nonPassingConditions.push(...statementResults.conditions);
            results.numberFailStatements += 1;
        }
    }
    return results;
}
module.exports = {
    evaluateBucketPolicy: evaluateBucketPolicy
};
