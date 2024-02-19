function getRequiredEnvVariable(name) {
    const value = process.env[name];

    if (!value) {
        process.stdout.write(`::warning::Environment variable '${name}' is not set. Aborting.\n`);
        process.exit(1);
    }

    return value;
}

module.exports = {getRequiredEnvVariable};
