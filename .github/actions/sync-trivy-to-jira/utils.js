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

module.exports = {
    severityToInt
};
