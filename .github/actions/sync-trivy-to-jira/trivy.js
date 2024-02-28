const {exec} = require('node:child_process');
const {ghaDebug, ghaWarning, ghaGroup} = require('./githubactions');

/**
 * Executes Trivy on an image and returns the output as JSON object.
 *
 * @param {String} image Image to check
 * @returns {Promise<*>} Promise resolving to a JSON object with Trivy's results
 */
async function executeTrivy(image) {
    // Check "image", so we don't execute arbitrary shell code O.o
    if (!image.match(/^[a-z0-9-]+(:[0-9a-z.-]+)?$/)) {
        throw new Error('Invalid image: ' + image);
    }
    const command = `trivy image ${image} --format json`;

    return await ghaGroup(`Running Trivy on image "${image}"`, async () => {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    ghaWarning(stderr);
                    reject(error);
                } else {
                    ghaDebug(`Executed Trivy on image ${image}. Output:\n${stdout}`);

                    resolve(JSON.parse(stdout));
                }
            });
        });
    });
}

module.exports = {executeTrivy};
