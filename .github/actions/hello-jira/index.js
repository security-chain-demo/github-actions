const {getRequiredEnvVariable} = require('./utils');
const {getJiraIssue} = require('./jira');

const jiraAuth = {
    domain: getRequiredEnvVariable('JIRA_DOMAIN'),
    email: getRequiredEnvVariable('JIRA_EMAIL'),
    token: getRequiredEnvVariable('JIRA_TOKEN')
};
const jiraIssue = getRequiredEnvVariable('JIRA_ISSUE');

getJiraIssue(jiraAuth, jiraIssue)
    .then(jsonData => {
        process.stdout.write(`::debug::Got JSON response: ${JSON.stringify(jsonData)}\n`);
        process.stdout.write(`::notice::Read issue's description: "${jsonData.fields.summary}"\n`);
        process.stdout.write(`::notice::Read issue's status: "${jsonData.fields.status.name}"\n`);
        process.exit(0);
    })
    .catch(err => {
        process.stdout.write(`::error::Got error: ${err.message}\n`);
        process.exit(1);
    });
