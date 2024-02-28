const fs = require('node:fs');
const {ghaGetRequiredInput, getRequiredEnvVariable, ghaGetInput, ghaWarning, ghaNotice} = require('./githubactions');
const {processServices} = require('./process-trivy-results');

// Inputs and environment

const servicesFile = ghaGetRequiredInput('services');
const minSeverity = ghaGetInput('min_severity') || 'HIGH';

let jiraPriorityIds = ghaGetInput('jira_priority_ids') || null;
if (jiraPriorityIds) {
    jiraPriorityIds = jiraPriorityIds.split(',');
    if (jiraPriorityIds.length !== 5) {
        ghaWarning(`Input 'jira_priority_ids' does not have exactly 5 IDs. Aborting.`)
        process.exit(1);
    }
}

const jiraConfig = {
    auth: {
        domain: getRequiredEnvVariable('JIRA_DOMAIN'),
        email: getRequiredEnvVariable('JIRA_EMAIL'),
        token: getRequiredEnvVariable('JIRA_TOKEN')
    },
    projectKey: ghaGetRequiredInput('jira_project_key'),
    issuetypeName: ghaGetRequiredInput('jira_issuetype_name'),
    serviceFieldId: ghaGetRequiredInput('jira_service_field_id'),
    serviceFieldName: ghaGetRequiredInput('jira_service_field_name'),
    teamFieldId: ghaGetRequiredInput('jira_team_field_id'),
    cveIdFieldId: ghaGetRequiredInput('jira_cve_id_field_id'),
    cveIdFieldName: ghaGetRequiredInput('jira_cve_id_field_name'),
    cveStatusFieldId: ghaGetRequiredInput('jira_cve_status_field_id'),
    priorityIds: jiraPriorityIds
};

const servicesText = fs.readFileSync(servicesFile, 'UTF-8');
const services = JSON.parse(servicesText);

const trivyConfig = {
    services,
    minSeverity
}

// main

Promise.resolve()
    .then(() => processServices(trivyConfig, jiraConfig))
    .then(() => {
        ghaNotice('All done.');
        process.exit(0);
    })
    .catch((err) => {
        ghaWarning('Caught an error: ' + err);
        process.exit(1);
    });
