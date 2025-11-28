/**
 * Admin Route - Contains Command Injection vulnerabilities
 */

const express = require('express');
const router = express.Router();
const { exec, spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

// VULNERABILITY: CWE-78 - Command Injection via exec (Line 13)
router.post('/backup', (req, res) => {
    const { filename } = req.body;
    exec(`tar -czf /backups/${filename}.tar.gz /data`, (error, stdout, stderr) => {
        if (error) {
            res.status(500).json({ error: stderr });
        } else {
            res.json({ success: true, output: stdout });
        }
    });
});

// VULNERABILITY: CWE-78 - Command Injection via execSync (Line 25)
router.get('/system-info', (req, res) => {
    const command = req.query.cmd || 'uname -a';
    const output = execSync(command).toString();
    res.json({ output });
});

// VULNERABILITY: CWE-78 - Command Injection via spawn (Line 32)
router.post('/convert', (req, res) => {
    const { inputFile, outputFile } = req.body;
    const process = spawn('convert', [inputFile, outputFile]);
    process.on('close', (code) => {
        res.json({ success: code === 0 });
    });
});

// VULNERABILITY: CWE-78 - Command Injection in ping utility (Line 41)
router.get('/ping', (req, res) => {
    const host = req.query.host;
    exec(`ping -c 4 ${host}`, (error, stdout) => {
        res.json({ output: stdout || error.message });
    });
});

// VULNERABILITY: CWE-22 - Path Traversal in file read (Line 49)
router.get('/logs', (req, res) => {
    const filename = req.query.file;
    const logPath = path.join('/var/log', filename);
    const content = fs.readFileSync(logPath, 'utf8');
    res.send(content);
});

// VULNERABILITY: CWE-22 - Path Traversal in file download (Line 57)
router.get('/download', (req, res) => {
    const requestedFile = req.query.path;
    const filePath = `/uploads/${requestedFile}`;
    res.download(filePath);
});

// VULNERABILITY: CWE-22 - Path Traversal in file write (Line 64)
router.post('/save-config', (req, res) => {
    const { filename, content } = req.body;
    const configPath = path.join('/configs', filename);
    fs.writeFileSync(configPath, content);
    res.json({ success: true });
});

// VULNERABILITY: CWE-78 - Command Injection via shell parameter (Line 72)
router.post('/git-clone', (req, res) => {
    const { repoUrl, branch } = req.body;
    exec(`git clone -b ${branch} ${repoUrl} /tmp/repo`, (error, stdout, stderr) => {
        res.json({ success: !error, output: stdout, error: stderr });
    });
});

// VULNERABILITY: CWE-22 - Path Traversal in directory listing (Line 80)
router.get('/list-files', (req, res) => {
    const dir = req.query.dir || '/uploads';
    const files = fs.readdirSync(dir);
    res.json({ files });
});

module.exports = router;
