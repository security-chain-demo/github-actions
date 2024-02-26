function _variableNameToEnvVariableName(variableName) {
    return 'INPUT_' + variableName.replace(/ /g, '_').toUpperCase();
}

function getRequiredEnvVariable(name) {
    const value = process.env[name];

    if (!value) {
        ghaWarning(`Environment variable '${name}' is not set. Aborting.`)
        process.exit(1);
    }

    return value;
}

function ghaGetRequiredInput(variableName) {
    return getRequiredEnvVariable(_variableNameToEnvVariableName(variableName));
}

function ghaGetInput(variableName) {
    return process.env[_variableNameToEnvVariableName(variableName)];
}

function _ghaOutputLog(level, text) {
    text
        .split('\n')
        .forEach(line => process.stdout.write(`::${level}::${line}\n`));
}

function ghaWarning(text) {
    _ghaOutputLog('warning', text);
}

function ghaNotice(text) {
    _ghaOutputLog('notice', text);
}

function ghaDebug(text) {
    _ghaOutputLog('debug', text);
}

async function ghaGroup(groupName, asyncFunc) {
    process.stdout.write(`::group::${groupName}\n`);
    const result = await asyncFunc();
    process.stdout.write('::endgroup::\n');

    return result;
}

module.exports = {
    getRequiredEnvVariable,
    ghaGetRequiredInput,
    ghaGetInput,
    ghaWarning,
    ghaNotice,
    ghaDebug,
    ghaGroup
};
