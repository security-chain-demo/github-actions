const {trivyImageToSBOM, trivyScanSBOM} = require('./trivy');
const {syncCVEsToJira} = require('./sync-to-jira');
const {ghaDebug, ghaWarning, ghaGroup, ghaNotice} = require('./githubactions');

/**
 * Processes all services.
 *
 * @param {Object} trivyConfig configuration for Trivy including all services to analyse
 * @param {Object} jiraConfig configuration to sync to JIRA
 * @returns {Promise<void>}
 */
async function processServices(trivyConfig, jiraConfig) {
    for (const serviceName of Object.keys(trivyConfig.services)) {
        const service = trivyConfig.services[serviceName];
        await processService(serviceName, service, trivyConfig, jiraConfig);
    }
}

/**
 * Processes one service: Executes Trivy, processes its results and syncs to JIRA
 *
 * @param {String} serviceName service's name
 * @param {{image: String, jiraTeamId: String}} service service's data
 * @param {Object} trivyConfig configuration for Trivy including all services to analyse
 * @param {Object} jiraConfig configuration to sync to JIRA
 * @returns {Promise<void>}
 */
async function processService(serviceName, service, trivyConfig, jiraConfig) {
    const image = service.image;
    const jiraTeamId = service.jiraTeamId;

    if (!image) {
        ghaWarning(`Service ${serviceName} does not have an image assigned. Aborting.`)
        process.exit(1);
    }
    if (!jiraTeamId) {
        ghaWarning(`Service ${serviceName} does not have a jiraTeamId assigned. Aborting.`)
        process.exit(1);
    }

    const sbomFile = await trivyImageToSBOM(image);
    const trivyScanResultsJson = await trivyScanSBOM(sbomFile);
    const cvesById = await processTrivyResult(image, trivyScanResultsJson, trivyConfig.minSeverity);

    await syncCVEsToJira(serviceName, service, cvesById, jiraConfig);
}

/**
 * Transforms a string `severity` into an int for comparison.
 * "greater" = "more critical", "lesser" = "less critical".
 *
 * @param severity as string
 * @returns {number}
 */
function severityToInt(severity) {
    switch (severity) {
        case 'CRITICAL': return 4;
        case 'HIGH': return 3;
        case 'MEDIUM': return 2;
        case 'LOW': return 1;
        case 'UNKNOWN': return 0;
        default: return -1;
    }
}

/**
 * Processes Trivy results.
 *
 * We group the result by CVE ID. Multiple packages can be affected by the same CVE.
 * We report the CVE as a unit, listing the affected packages in the text.
 *
 * @param {String} image
 * @param {Object} trivyScanResultsJson Trivy vulnerability result for this image as JSON data
 * @param {String} minSeverity minimal severity to include a CVE into the result (`CRITICAL`,`HIGH`, ...)
 * @returns {Promise<Object>} Promise resolving to the CVEs by ID
 */
async function processTrivyResult(image, trivyScanResultsJson, minSeverity) {
    return await ghaGroup(`Analysing Trivy results for image "${image}"`, async () => {
        const cvesById = {};

        for (const result of trivyScanResultsJson.Results) {
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

module.exports = {processServices};
