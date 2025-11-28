/**
 * File Utilities - Contains Path Traversal vulnerabilities
 */

const fs = require('fs');
const path = require('path');

const UPLOAD_DIR = '/uploads';
const CONFIG_DIR = '/configs';

// VULNERABILITY: CWE-22 - Path Traversal in read (Line 13)
const readUserFile = (filename) => {
    const filePath = path.join(UPLOAD_DIR, filename);
    return fs.readFileSync(filePath, 'utf8');
};

// VULNERABILITY: CWE-22 - Path Traversal in write (Line 19)
const writeUserFile = (filename, content) => {
    const filePath = path.join(UPLOAD_DIR, filename);
    fs.writeFileSync(filePath, content);
};

// VULNERABILITY: CWE-22 - Path Traversal in delete (Line 25)
const deleteUserFile = (filename) => {
    const filePath = path.join(UPLOAD_DIR, filename);
    fs.unlinkSync(filePath);
};

// VULNERABILITY: CWE-22 - Path Traversal in directory read (Line 31)
const listDirectory = (dirname) => {
    const dirPath = path.join(UPLOAD_DIR, dirname);
    return fs.readdirSync(dirPath);
};

// VULNERABILITY: CWE-22 - Path Traversal without any path join (Line 37)
const readRawPath = (userPath) => {
    return fs.readFileSync(userPath, 'utf8');
};

// VULNERABILITY: CWE-22 - Path Traversal in config read (Line 42)
const getConfig = (configName) => {
    const configPath = `${CONFIG_DIR}/${configName}.json`;
    const content = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(content);
};

// Safe example - Path validation (NOT a vulnerability)
const safeReadFile = (filename) => {
    // Validate filename doesn't contain path traversal
    if (filename.includes('..') || filename.includes('/')) {
        throw new Error('Invalid filename');
    }
    const filePath = path.join(UPLOAD_DIR, filename);
    // Also check resolved path is within upload dir
    const resolvedPath = path.resolve(filePath);
    if (!resolvedPath.startsWith(UPLOAD_DIR)) {
        throw new Error('Access denied');
    }
    return fs.readFileSync(resolvedPath, 'utf8');
};

module.exports = {
    readUserFile,
    writeUserFile,
    deleteUserFile,
    listDirectory,
    readRawPath,
    getConfig,
    safeReadFile
};
