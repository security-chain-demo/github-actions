const {mkdirSync, statSync} = require('node:fs')
const {exec} = require('node:child_process');
const {ghaDebug, ghaWarning, ghaGroup, ghaNotice} = require('./githubactions');

/**
 * Executes Trivy on an image to generate an SBOM.
 * SBOM is persisted in directory `sbom` (created if not existing)
 * and the resulting file path is returned.
 *
 * @param {String} image Image to process
 * @returns {Promise<String>} Promise resolving a file path, containg to SBOM
 */
async function trivyImageToSBOM(image) {
    // Check "image", so we don't execute arbitrary shell code O.o
    if (!image.match(/^[a-z0-9-]+(:[0-9a-z.-]+)?$/)) {
        throw new Error('Invalid image: ' + image);
    }

    // Create SBOM directory
    const sbomDirectory = 'sbom';
    try {
        mkdirSync(sbomDirectory);
    } catch (e) {
        // Ignore. Happens when directory already exists
    }

    const imageNameSafe = image.replace(':', '!'); // ':' can make problems in some FS, better avoid it.
    const sbomFile = `${sbomDirectory}/${imageNameSafe}.cyclonedx.json`;

    // Use cached file if present.
    // Vulnerabilities could change over time. A specific image will not change (*).
    //
    // *) Note: During development it's possible to use the same image (i.e. name+version) and change its
    //    dependencies/base image. We assume this will not be done. Application code will change multiple time
    //    during the lifetime of a Pull Request. But not the dependencies/base image. If such a change is performed,
    //    we assume the image's version will be changed, too.

    let cacheFileExists = true;
    try {
        statSync(sbomFile);
    } catch (e) {
        cacheFileExists = false;
    }

    if (cacheFileExists) {
        ghaNotice(`SBOM for image ${image} already exists in cached file ${sbomFile}. We skip running Trivy for this.`);
        return Promise.resolve(sbomFile);
    }

    // Run Trivy to generate the SBOM

    const command = `trivy image ${image} --format cyclonedx --output ${sbomFile}`;

    return await ghaGroup(`Running Trivy to generate SBOM for image "${image}" `, async () => {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    ghaWarning(stderr);
                    reject(error);
                } else {
                    ghaDebug(`Executed Trivy to generate SBOM for image ${image}.`);
                    ghaDebug(`Output is written into file ${sbomFile}.`);

                    resolve(sbomFile);
                }
            });
        });
    });
}

/**
 * Executes Trivy vulnerability scan on an SBOM and returns the output as JSON object.
 *
 * @param {String} sbomFile path to SBOM file (must be safe to be used for shell command line!)
 * @returns {Promise<*>} Promise resolving to a JSON object with Trivy's results
 */
async function trivyScanSBOM(sbomFile) {
    const command = `trivy sbom ${sbomFile} --format json`;

    return await ghaGroup(`Running Trivy vulnerability scan on SBOM "${sbomFile}"`, async () => {
        return new Promise((resolve, reject) => {
            exec(command, (error, stdout, stderr) => {
                if (error) {
                    ghaWarning(stderr);
                    reject(error);
                } else {
                    ghaDebug(`Executed Trivy vulnerability scan on SBOM ${sbomFile}. Output:\n${stdout}`);

                    resolve(JSON.parse(stdout));
                }
            });
        });
    });
}

module.exports = {trivyImageToSBOM, trivyScanSBOM};
