const https = require('node:https');

function getRequiredEnvVariable(name) {
    const value = process.env[name];

    if (!value) {
        process.stdout.write(`::warning::Environment variable '${name}' is not set. Aborting.\n`);
        process.exit(1);
    }

    return value
}

const jiraDomain = getRequiredEnvVariable('JIRA_DOMAIN');
const jiraEmail = getRequiredEnvVariable('JIRA_EMAIL');
const jiraToken = getRequiredEnvVariable('JIRA_TOKEN');

const jiraIssue = getRequiredEnvVariable('JIRA_ISSUE');

const authorizationBasic = Buffer
    .from(`${jiraEmail}:${jiraToken}`)
    .toString('base64')

https.get(`https://${jiraDomain}.atlassian.net/rest/api/2/issue/${jiraIssue}`, {
    headers: {
        'Authorization': `Basic ${authorizationBasic}`
    }
}, res => {
    process.stdout.write(`::notice::Got HTTP status code: ${res.statusCode}\n`);

    let data = '';
    res.on('data', chunk => {
        data += chunk;
    });

    res.on('end', () => {
        const jsonData = JSON.parse(data);
        process.stdout.write(`::debug::Got JSON response: ${data}\n`);
        process.stdout.write(`::notice::Read issue's description: "${jsonData.fields.summary}"\n`);
        process.stdout.write(`::notice::Read issue's status: "${jsonData.fields.status.name}"\n`);
        process.exit(0);
    });
}).on('error', err => {
    process.stdout.write(`::error::Got error: ${err.message}\n`);
    process.exit(1);
});
