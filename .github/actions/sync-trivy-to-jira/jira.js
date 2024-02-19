const https = require('node:https');

const buildAuthorizationBasic = (jiraAuth) => Buffer
    .from(`${jiraAuth.email}:${jiraAuth.token}`)
    .toString('base64');

function jiraGetIssue(jiraAuth, jiraIssue) {
    return new Promise((resolve, reject) => {
        https.get(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue/${jiraIssue}`, {
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
            }
        }, res => {
            process.stdout.write(`::notice::Got HTTP status code: ${res.statusCode}\n`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                const jsonData = JSON.parse(data);

                resolve(jsonData);
            });
        }).on('error', err => {
            reject(err);
        });
    });
}

function jiraCreateIssue(jiraAuth, projectKey, issuetypeName, summary, description, customFields) {
    const jsonData = {
        fields: {
            project: {
                key: projectKey
            },
            issuetype: {
                name: issuetypeName
            },
            summary,
            description,
            ...customFields
        }
    };

    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(jsonData);

        const request = https.request(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
                'Content-Type': 'application/json'
            }
        }, res => {
            process.stdout.write(`::notice::Got HTTP status code: ${res.statusCode}\n`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                const jsonData = JSON.parse(data);

                if (res.statusCode === 201) {
                    resolve(jsonData);
                } else {
                    reject(`Got invalid status code ${res.statusCode}, data = ${data}`);
                }
            });
        }).on('error', err => {
            reject(err);
        });

        request.write(postData);
        request.end();
    });
}

module.exports = {jiraGetIssue, jiraCreateIssue};