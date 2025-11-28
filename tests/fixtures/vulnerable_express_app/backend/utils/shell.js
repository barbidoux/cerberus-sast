/**
 * Shell Utilities - Contains Command Injection vulnerabilities
 */

const { exec, execSync, spawn } = require('child_process');

// VULNERABILITY: CWE-78 - Command Injection via exec wrapper (Line 9)
const runCommand = (command, callback) => {
    exec(command, (error, stdout, stderr) => {
        callback(error, stdout, stderr);
    });
};

// VULNERABILITY: CWE-78 - Command Injection via execSync wrapper (Line 16)
const runCommandSync = (command) => {
    return execSync(command).toString();
};

// VULNERABILITY: CWE-78 - Command Injection via spawn wrapper (Line 21)
const spawnProcess = (command, args) => {
    return spawn(command, args);
};

// VULNERABILITY: CWE-78 - Command Injection in video processing (Line 26)
const processVideo = (inputPath, outputPath, options) => {
    const cmd = `ffmpeg -i ${inputPath} ${options} ${outputPath}`;
    return new Promise((resolve, reject) => {
        exec(cmd, (error, stdout, stderr) => {
            if (error) reject(error);
            else resolve({ stdout, stderr });
        });
    });
};

// VULNERABILITY: CWE-78 - Command Injection in image resize (Line 38)
const resizeImage = (imagePath, width, height) => {
    const cmd = `convert ${imagePath} -resize ${width}x${height} ${imagePath}`;
    execSync(cmd);
};

// VULNERABILITY: CWE-78 - Command Injection via shell option (Line 44)
const runWithShell = (userInput) => {
    exec(userInput, { shell: '/bin/bash' }, (error, stdout) => {
        console.log(stdout);
    });
};

// Safe example - Using spawn with array args (NOT a vulnerability)
const safePing = (host) => {
    // Arguments passed as array, not concatenated string
    return spawn('ping', ['-c', '4', host]);
};

module.exports = {
    runCommand,
    runCommandSync,
    spawnProcess,
    processVideo,
    resizeImage,
    runWithShell,
    safePing
};
