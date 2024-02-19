const {getRequiredEnvVariable} = require('./utils');
const {getJiraIssue, createJiraIssue} = require('./jira');

const jiraAuth = {
    domain: getRequiredEnvVariable('JIRA_DOMAIN'),
    email: getRequiredEnvVariable('JIRA_EMAIL'),
    token: getRequiredEnvVariable('JIRA_TOKEN')
};
const jiraIssue = getRequiredEnvVariable('JIRA_ISSUE');

const getIssue = getJiraIssue(jiraAuth, jiraIssue)
    .then(jsonData => {
        process.stdout.write(`::debug::Got JSON response: ${JSON.stringify(jsonData)}\n`);
        process.stdout.write(`::notice::Read issue's description: "${jsonData.fields.summary}"\n`);
        process.stdout.write(`::notice::Read issue's status: "${jsonData.fields.status.name}"\n`);
    })
    .catch(err => {
        process.stdout.write(`::error::Got error: ${err}\n`);
        process.exit(1);
    });

const createTask = createJiraIssue(
    jiraAuth,
    'SEC',
    'Task',
    'Hello JIRA',
    'Hi there.\n\nThis is an automatically posted issue purely over the API :-)'
)
    .then(jsonData => {
        process.stdout.write(`::debug::Got JSON response: ${JSON.stringify(jsonData)}\n`);
        process.stdout.write('::notice::Successfully created new issue.\n');
        process.stdout.write(`::notice::New issue has ID ${jsonData.id} and key "${jsonData.key}".\n`);
    })
    .catch(err => {
        process.stdout.write(`::error::Got error: ${err}\n`);
        process.exit(1);
    });

const createSecurityIssue = createJiraIssue(
    jiraAuth,
    'SEC',
    'Security issue',
    'Library FOO is dangerous',
    '…just kidding, but this is an issue with a custom issue type'
)
    .then(jsonData => {
        process.stdout.write(`::debug::Got JSON response: ${JSON.stringify(jsonData)}\n`);
        process.stdout.write('::notice::Successfully created new issue.\n');
        process.stdout.write(`::notice::New issue has ID ${jsonData.id} and key "${jsonData.key}".\n`);
    })
    .catch(err => {
        process.stdout.write(`::error::Got error: ${err}\n`);
        process.exit(1);
    });

Promise.all([getIssue, createTask, createSecurityIssue])
    .then(() => {
        process.stdout.write('::notice::All JIRA tasks successful.\n');
        process.exit(0);
    });
