const fs = require('node:fs');
const {severityToInt, severityToIndex} = require('./utils');
const {ghaGetRequiredInput, getRequiredEnvVariable, ghaGetInput, ghaDebug, ghaWarning, ghaGroup, ghaNotice} = require('./githubactions');
const {jiraSearchIssueByJQL, jiraCreateIssue, jiraEditIssue} = require('./jira');

// Inputs and environment

const trivyInputFile = ghaGetRequiredInput('trivy_results');
const minSeverity = ghaGetInput('min_severity') || 'HIGH';
const jiraProjectKey = ghaGetRequiredInput('jira_project_key');
const jiraIssuetypeName = ghaGetRequiredInput('jira_issuetype_name');
const jiraTeamFieldId = ghaGetRequiredInput('jira_team_field_id');
const jiraTeamFieldName = ghaGetRequiredInput('jira_team_field_name');
const jiraTeamFieldValue = ghaGetRequiredInput('jira_team_field_value');
const jiraCveIdFieldId = ghaGetRequiredInput('jira_cve_id_field_id');
const jiraCveIdFieldName = ghaGetRequiredInput('jira_cve_id_field_name');
const jiraCveStatusFieldId = ghaGetRequiredInput('jira_cve_status_field_id');

let input = ghaGetInput('jira_priority_ids') || null;
if (input) {
    input = input.split(',');
    if (input.length !== 5) {
        ghaWarning(`Input 'jira_priority_ids' does not have exactly 5 IDs. Aborting.`)
        process.exit(1);
    }
}
const jiraPriorityIds = input;

const jiraAuth = {
    domain: getRequiredEnvVariable('JIRA_DOMAIN'),
    email: getRequiredEnvVariable('JIRA_EMAIL'),
    token: getRequiredEnvVariable('JIRA_TOKEN')
};

// Read Trivy results

const text = fs.readFileSync(trivyInputFile, 'UTF-8');
const json = JSON.parse(text);

// Process Trivy results
//
// We group the result by CVE ID. Multiple packages can be affected by the same CVE.
// We report the CVE as a unit, listing the affected packages in the text.

async function processTrivyResult() {
    return await ghaGroup('Analysing Trivy results', async () => {
        const cvesById = {};

        for (const result of json.Results) {
            for (const vulnerability of (result.Vulnerabilities || [])) { // Vulnerabilities can be null
                ghaDebug('Vulnerability: ' + JSON.stringify(vulnerability));

                // Always available fields
                // https://aquasecurity.github.io/trivy/v0.17.2/examples/report/#json
                const vulId = vulnerability.VulnerabilityID;
                const vulPackageName = vulnerability.PkgName;
                const vulInstalledVersion = vulnerability.InstalledVersion;
                const vulSeverity = vulnerability.Severity;

                ghaNotice(`Found vulnerability ${vulId} with severity ${vulSeverity} on package ${vulPackageName}.`);

                if (severityToInt(vulSeverity) < severityToInt(minSeverity)) {
                    ghaNotice(`Ignoring for now, as it's not ${minSeverity}.`);
                    continue;
                }

                if (!cvesById[vulId]) {
                    cvesById[vulId] = {
                        id: vulId,
                        severity: vulSeverity,
                        title: vulnerability.Title || vulPackageName,
                        description: vulnerability.Description || 'No description available.',
                        packageNames: [vulPackageName],
                        installedVersion: vulInstalledVersion,
                        fixedVersion: vulnerability.FixedVersion || "No fix version available.",
                        status: vulnerability.Status || "unknown",
                        primaryUrl: vulnerability.PrimaryURL || "No information available.",
                        references: vulnerability.References || [],
                    };
                } else {
                    // Add package
                    cvesById[vulId].packageNames.push(vulPackageName);

                    // Usually the severity should be the same.
                    // Just in case, we take the maximum.
                    if (severityToInt(vulSeverity) > severityToInt(cvesById[vulId].severity)) {
                        cvesById[vulId].severity = vulSeverity;
                    }

                    // We keep the other information from the first found issue.
                    // It seems Trivy reports the same, which makes sense as the data depends on the CVE,
                    // not the package.
                }
            }
        }

        ghaDebug('cvesById: ' + JSON.stringify(cvesById));
        return cvesById;
    });
}

// Sync CVEs to JIRA
//
// For now, we process each CVE separately to test updating.
// A later version could assume issue text are not edited,
// so we save lots of API calls to JIRA to only touch updated issues.

function buildSummaryAndDescription(cve) {
    let summary = cve.title;

    let description = '';
    description += `Trivy found a vulnerability in one or more packages.`;
    description += `\n\n*Severity:*\n${cve.severity}`;
    description += `\n\n*Affected packages*:\n${cve.packageNames.join(', ')}`;
    description += `\n\n*Versions*:\n|Installed|${cve.installedVersion}|\n|Fix in|${cve.fixedVersion}|`;
    description += `\n\n*Primary URL*:\n${cve.primaryUrl}`;
    description += `\n\n*Description:*\n${cve.description}`;
    description += `\n\n*References*:\n${cve.references.map(url => `- ${url}`).join('\n')}`;

    return {summary, description};
}

async function syncCVEsToJira(cvesById) {
    await ghaGroup('Syncing results to JIRA', async () => {
        for (const cveId of Object.keys(cvesById)) {
            const cve = cvesById[cveId];
            ghaDebug('cve: ' + JSON.stringify(cve));

            const escapeJQL = (str) => str; // TODO did not check what special chars JIRA allows, for now, just pass-through
            const jql =
                'project = "' + escapeJQL(jiraProjectKey) + '" ' +
                'and "' + escapeJQL(jiraTeamFieldName) + '" = "' + escapeJQL(jiraTeamFieldValue) + '"' +
                'and "' + escapeJQL(jiraCveIdFieldName) + '" ~ "\\\"' + escapeJQL(cveId) + '\\\""'; // '\"' needs for an exact match with '~', see https://confluence.atlassian.com/jirasoftwareserver/advanced-searching-operators-reference-939938745.html
            const searchResult = await jiraSearchIssueByJQL(jiraAuth, jql);

            const {summary, description} = buildSummaryAndDescription(cve);

            if (searchResult.total) {
                // Issue exists
                const jiraIssueId = searchResult.issues[0].id;
                const jiraIssueKey = searchResult.issues[0].key;

                ghaNotice(`JIRA issue ${jiraIssueKey} already exists for team ${jiraTeamFieldValue} and CVE ${cveId}. Updating.`);

                await jiraEditIssue(jiraAuth, jiraIssueId, summary, description);

                ghaNotice(`JIRA issue ${jiraIssueKey} updated.`);
            }
            else {
                // Issue does not exist

                ghaNotice(`No JIRA issue exists for team ${jiraTeamFieldValue} and CVE ${cveId}. Creating.`);

                // Set priority only when creating the issue.
                // Users may triage the issue and change the priority in JIRA.
                // We leave that untouched when updating an issue.
                const priorityId = (jiraPriorityIds) ? jiraPriorityIds[severityToIndex(cve.severity)] : null;

                const customFields = {
                    [jiraTeamFieldId]: jiraTeamFieldValue,
                    [jiraCveIdFieldId]: cve.id,
                    [jiraCveStatusFieldId]: cve.status,
                };
                const response = await jiraCreateIssue(jiraAuth, jiraProjectKey, jiraIssuetypeName, priorityId, summary, description, customFields);
                const createIssueKey = response.key;

                ghaNotice(`Created new JIRA issue ${createIssueKey} for CVE ${cveId}.`);
            }
        }
    });
}

// main

Promise.resolve()
    .then(() => processTrivyResult())
    .then(cvesById => syncCVEsToJira(cvesById))
    .then(() => {
        ghaNotice('All done.');
        process.exit(0);
    });
