const https = require('node:https');

function getRequiredEnvVariable(name) {
    const value = process.env[name];

    if (!value) {
        process.stdout.write(`::warning::Environment variable '${name}' is not set. Aborting.\n`);
        process.exit(1);
    }

    return value;
}

function getJiraIssue(jiraAuth, jiraIssue) {
    const authorizationBasic = Buffer
        .from(`${jiraAuth.email}:${jiraAuth.token}`)
        .toString('base64');

    return new Promise((resolve, reject) => {
        https.get(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue/${jiraIssue}`, {
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
                resolve(data);
            });
        }).on('error', err => {
            reject(err);
        });
    });
}

const jiraAuth = {
    domain: getRequiredEnvVariable('JIRA_DOMAIN'),
    email: getRequiredEnvVariable('JIRA_EMAIL'),
    token: getRequiredEnvVariable('JIRA_TOKEN')
};
const jiraIssue = getRequiredEnvVariable('JIRA_ISSUE');

getJiraIssue(jiraAuth, jiraIssue)
    .then(data => {
        const jsonData = JSON.parse(data);
        process.stdout.write(`::debug::Got JSON response: ${data}\n`);
        process.stdout.write(`::notice::Read issue's description: "${jsonData.fields.summary}"\n`);
        process.stdout.write(`::notice::Read issue's status: "${jsonData.fields.status.name}"\n`);
        process.exit(0);
    })
    .catch(err => {
        process.stdout.write(`::error::Got error: ${err.message}\n`);
        process.exit(1);
    });
