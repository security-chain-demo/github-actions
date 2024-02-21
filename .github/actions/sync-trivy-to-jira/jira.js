const https = require('node:https');
const {ghaDebug} = require('./githubactions');

const buildAuthorizationBasic = (jiraAuth) => Buffer
    .from(`${jiraAuth.email}:${jiraAuth.token}`)
    .toString('base64');

async function jiraGetIssue(jiraAuth, jiraIssue) {
    return new Promise((resolve, reject) => {
        https.get(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue/${jiraIssue}`, {
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
            }
        }, res => {
            ghaDebug(`Got HTTP status code: ${res.statusCode}`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                ghaDebug(`Got HTTP data: ${data}`);
                const jsonData = JSON.parse(data);

                resolve(jsonData);
            });
        }).on('error', err => {
            reject(err);
        });
    });
}

async function jiraSearchIssueByJQL(jiraAuth, jql) {
    const jqlEncoded = encodeURIComponent(jql);

    return new Promise((resolve, reject) => {
        https.get(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/search?jql=${jqlEncoded}`, {
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
            }
        }, res => {
            ghaDebug(`Got HTTP status code: ${res.statusCode}`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                ghaDebug(`Got HTTP data: ${data}`);
                const jsonData = JSON.parse(data);

                resolve(jsonData);
            });
        }).on('error', err => {
            reject(err);
        });
    });
}

async function jiraCreateIssue(jiraAuth, projectKey, issuetypeName, priorityId, summary, description, customFields) {
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

    if (priorityId) {
        jsonData.fields.priority = {
            id: priorityId
        };
    }

    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(jsonData);

        const request = https.request(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue`, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
                'Content-Type': 'application/json'
            }
        }, res => {
            ghaDebug(`Got HTTP status code: ${res.statusCode}`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                ghaDebug(`Got HTTP data: ${data}`);
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

async function jiraEditIssue(jiraAuth, issueId, summary, description) {
    const jsonData = {
        fields: {
            summary,
            description
        }
    };

    return new Promise((resolve, reject) => {
        const postData = JSON.stringify(jsonData);

        const request = https.request(`https://${jiraAuth.domain}.atlassian.net/rest/api/2/issue/${issueId}`, {
            method: 'PUT',
            headers: {
                'Authorization': `Basic ${buildAuthorizationBasic(jiraAuth)}`,
                'Content-Type': 'application/json'
            }
        }, res => {
            ghaDebug(`Got HTTP status code: ${res.statusCode}`);

            let data = '';
            res.on('data', chunk => {
                data += chunk;
            });

            res.on('end', () => {
                ghaDebug(`Got HTTP data: ${data}`);

                if (res.statusCode === 204) {
                    resolve();
                } else {
                    reject(`Got invalid status code ${res.statusCode}.`);
                }
            });
        }).on('error', err => {
            reject(err);
        });

        request.write(postData);
        request.end();
    });
}

module.exports = {jiraGetIssue, jiraSearchIssueByJQL, jiraCreateIssue, jiraEditIssue};