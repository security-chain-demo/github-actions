function _variableNameToEnvVariableName(variableName) {
    return 'INPUT_' + variableName.replaceAll('-', '_').toUpperCase();
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

function ghaWarning(text) {
    process.stdout.write(`::warning::${text}\n`);
}

function ghaNotice(text) {
    process.stdout.write(`::notice::${text}\n`);
}

function ghaDebug(text) {
    process.stdout.write(`::debug::${text}\n`);
}

function ghaGroup(groupName, bodyFunc) {
    process.stdout.write(`::group::${groupName}\n`);
    bodyFunc();
    process.stdout.write('::endgroup::\n');
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