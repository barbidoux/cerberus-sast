/**
 * Admin Component - Contains bypassSecurityTrust vulnerabilities
 */

import { Component, OnInit } from '@angular/core';
import { DomSanitizer, SafeHtml, SafeUrl, SafeResourceUrl } from '@angular/platform-browser';
import { HttpClient } from '@angular/common/http';

@Component({
    selector: 'app-admin',
    template: `
        <div class="admin-panel">
            <div [innerHTML]="trustedHtml"></div>
            <iframe [src]="trustedUrl"></iframe>
            <a [href]="trustedLink">Download</a>
        </div>
    `
})
export class AdminComponent implements OnInit {
    trustedHtml: SafeHtml = '';
    trustedUrl: SafeResourceUrl = '';
    trustedLink: SafeUrl = '';

    constructor(
        private sanitizer: DomSanitizer,
        private http: HttpClient
    ) {}

    ngOnInit(): void {
        this.loadUserContent();
    }

    // VULNERABILITY: CWE-79 - XSS via bypassSecurityTrustHtml (Line 33)
    loadUserContent(): void {
        this.http.get<{content: string}>('/api/admin/content').subscribe(data => {
            // Dangerous: bypasses Angular's built-in XSS protection
            this.trustedHtml = this.sanitizer.bypassSecurityTrustHtml(data.content);
        });
    }

    // VULNERABILITY: CWE-79 - XSS via bypassSecurityTrustScript (Line 41)
    loadScript(scriptContent: string): void {
        const trustedScript = this.sanitizer.bypassSecurityTrustScript(scriptContent);
        // Execute trusted script...
    }

    // VULNERABILITY: CWE-918 - SSRF via bypassSecurityTrustResourceUrl (Line 47)
    loadIframe(userUrl: string): void {
        this.trustedUrl = this.sanitizer.bypassSecurityTrustResourceUrl(userUrl);
    }

    // VULNERABILITY: CWE-79 - Open redirect via bypassSecurityTrustUrl (Line 52)
    createLink(userUrl: string): void {
        this.trustedLink = this.sanitizer.bypassSecurityTrustUrl(userUrl);
    }

    // VULNERABILITY: CWE-79 - XSS via bypassSecurityTrustStyle (Line 57)
    applyUserStyle(styleContent: string): void {
        const trustedStyle = this.sanitizer.bypassSecurityTrustStyle(styleContent);
        // Apply style...
    }

    // VULNERABILITY: CWE-79 - XSS rendering raw user HTML (Line 63)
    renderRawHtml(html: string): void {
        const container = document.getElementById('admin-container');
        if (container) {
            container.innerHTML = html;
        }
    }
}
