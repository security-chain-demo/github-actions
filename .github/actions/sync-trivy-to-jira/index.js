const fs = require('node:fs');
const {severityToInt} = require('./utils');
const {ghaGetRequiredInput, getRequiredEnvVariable, ghaGetInput, ghaDebug, ghaGroup, ghaWarning, ghaNotice} = require('./githubactions');
const {jiraCreateIssue} = require('./jira');

// Inputs and environment

const trivyInputFile = ghaGetRequiredInput('trivy-results');
const minSeverity = ghaGetInput('min-severity') || 'HIGH';
const jiraProjectKey = ghaGetRequiredInput('jira-project-key');
const jiraIssuetypeName = ghaGetRequiredInput('jira-issuetype-name');
const jiraCveIdFieldId = ghaGetRequiredInput('jira-cve-id-field-id');

const jiraAuth = {
    domain: getRequiredEnvVariable('JIRA_DOMAIN'),
    email: getRequiredEnvVariable('JIRA_EMAIL'),
    token: getRequiredEnvVariable('JIRA_TOKEN')
};

// Read Trivy results

const text = fs.readFileSync(trivyInputFile, 'UTF-8');
const json = JSON.parse(text);

// Process Trivy results

for (const result of json.Results) {
    ghaGroup(`Analysing results for target "${result.Target}"`, () => {
        for (const vulnerability of (result.Vulnerabilities || [])) { // Vulnerabilities can be null
            ghaDebug('Vulnerability: ' + JSON.stringify(vulnerability));

            // Always available fields
            // https://aquasecurity.github.io/trivy/v0.17.2/examples/report/#json
            const vulId = vulnerability.VulnerabilityID;
            const vulPackageName = vulnerability.PkgName;
            const vulInstalledVersion = vulnerability.InstalledVersion;
            const vulSeverity = vulnerability.Severity;

            ghaNotice(`Found vulnerability ${vulId} with severity ${vulSeverity}.`)

            if (severityToInt(vulSeverity) < severityToInt(minSeverity)) {
                ghaNotice(`Ignoring for now, as it's not ${minSeverity}.`);
                continue;
            }

            ghaNotice("Syncing to JIRA…");

            let summary = vulPackageName;
            if (vulnerability.Title) {
                summary = `${vulPackageName}: ${vulnerability.Title}`;
            }

            let description = '';
            description += `Trivy found a vulnerability in package \`${vulPackageName}\`.`;
            if (vulnerability.Description) {
                description += `\n\n**Description:**\n${vulnerability.Description}`;
            }

            customFields = {
                [jiraCveIdFieldId]: vulId
            };

            jiraCreateIssue(jiraAuth, jiraProjectKey, jiraIssuetypeName, summary, description, customFields);
        }
    });
}
