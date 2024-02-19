const https = require('node:https');

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

module.exports = {getJiraIssue};