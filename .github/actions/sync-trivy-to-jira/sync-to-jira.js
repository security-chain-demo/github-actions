const {ghaDebug, ghaGroup, ghaNotice} = require('./githubactions');
const {jiraSearchIssueByJQL, jiraCreateIssue, jiraEditIssue} = require('./jira');

/**
 * Builds summary and description to be used in a JIRA issue for the provided CVE.
 *
 * @param {Object} cve CVE data
 * @returns {{summary: string, description: string}} Summary and Description to be put into JIRA
 */
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

/**
 * Transforms a string `severity` into an int for index access.
 * 0 = "most critical", "4" = "least critical" (or "unknown").
 *
 * @param severity
 * @returns {number}
 */
function severityToIndex(severity) {
    switch (severity) {
        case 'CRITICAL': return 0;
        case 'HIGH': return 1;
        case 'MEDIUM': return 2;
        case 'LOW': return 3;
        case 'UNKNOWN': return 4;
        default: return 4;
    }
}

/**
 * Sync CVEs to JIRA
 *
 * For now, we process each CVE separately to test updating.
 * A later version could assume issue text are not edited,
 * so we save lots of API calls to JIRA to only touch updated issues.
 *
 * @param {String} serviceName
 * @param {{image: String, jiraTeamId: String}} service service's data
 * @param {Object} cvesById CVEs by ID
 * @param {Object} jiraConfig configuration to sync to JIRA
 * @returns {Promise<void>}
 */
async function syncCVEsToJira(serviceName, service, cvesById, jiraConfig) {
    await ghaGroup(`Syncing results for service '${serviceName}' to JIRA`, async () => {
        for (const cveId of Object.keys(cvesById)) {
            const cve = cvesById[cveId];
            ghaDebug('cve: ' + JSON.stringify(cve));

            const escapeJQL = (str) => str; // TODO did not check what special chars JIRA allows, for now, just pass-through
            const jql =
                'project = "' + escapeJQL(jiraConfig.projectKey) + '" ' +
                'and "' + escapeJQL(jiraConfig.serviceFieldName) + '" ~ \\\"' + escapeJQL(serviceName) + '\\\" ' + // '\"' needs for an exact match with '~', see https://confluence.atlassian.com/jirasoftwareserver/advanced-searching-operators-reference-939938745.html
                'and "' + escapeJQL(jiraConfig.cveIdFieldName) + '" ~ "\\\"' + escapeJQL(cveId) + '\\\""';
            const searchResult = await jiraSearchIssueByJQL(jiraConfig.auth, jql);

            const {summary, description} = buildSummaryAndDescription(cve);

            if (searchResult.total) {
                // Issue exists
                const jiraIssueId = searchResult.issues[0].id;
                const jiraIssueKey = searchResult.issues[0].key;

                ghaNotice(`JIRA issue ${jiraIssueKey} already exists for service ${serviceName} and CVE ${cveId}. Updating.`);

                await jiraEditIssue(jiraConfig.auth, jiraIssueId, summary, description);

                ghaNotice(`JIRA issue ${jiraIssueKey} updated.`);
            }
            else {
                // Issue does not exist

                ghaNotice(`No JIRA issue exists for service ${serviceName} and CVE ${cveId}. Creating.`);

                // Set priority only when creating the issue.
                // Users may triage the issue and change the priority in JIRA.
                // We leave that untouched when updating an issue.
                const priorityId = (jiraConfig.priorityIds) ? jiraConfig.priorityIds[severityToIndex(cve.severity)] : null;

                const customFields = {
                    [jiraConfig.serviceFieldId]: serviceName,
                    [jiraConfig.teamFieldId]: service.jiraTeamId,
                    [jiraConfig.cveIdFieldId]: cve.id,
                    [jiraConfig.cveStatusFieldId]: cve.status,
                };
                const response = await jiraCreateIssue(
                    jiraConfig.auth,
                    jiraConfig.projectKey,
                    jiraConfig.issuetypeName,
                    priorityId,
                    summary,
                    description,
                    customFields
                );
                const createIssueKey = response.key;

                ghaNotice(`Created new JIRA issue ${createIssueKey} for service ${serviceName} and CVE ${cveId}.`);
            }
        }
    });
}

module.exports = {syncCVEsToJira};
