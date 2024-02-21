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

module.exports = {
    severityToInt,
    severityToIndex
};
