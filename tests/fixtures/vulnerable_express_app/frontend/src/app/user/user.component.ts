/**
 * User Component - Contains template injection and XSS vulnerabilities
 */

import { Component, Input, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

@Component({
    selector: 'app-user',
    template: `
        <div class="user-profile">
            <h1>{{ userName }}</h1>
            <div class="bio" [innerHTML]="userBio"></div>
            <div #profileContent></div>
        </div>
    `
})
export class UserComponent implements OnInit {
    // VULNERABILITY: CWE-79 - XSS via @Input without sanitization (Line 20)
    @Input() userName: string = '';
    @Input() userBio: string = '';

    constructor(private route: ActivatedRoute) {}

    ngOnInit(): void {
        // VULNERABILITY: CWE-79 - XSS via route parameter (Line 27)
        this.route.params.subscribe(params => {
            this.userName = params['name'];
            this.loadUserProfile(params['id']);
        });
    }

    // VULNERABILITY: CWE-79 - XSS via innerHTML assignment (Line 34)
    loadUserProfile(userId: string): void {
        fetch(`/api/users/${userId}`)
            .then(res => res.json())
            .then(user => {
                const profileDiv = document.querySelector('.user-profile');
                if (profileDiv) {
                    profileDiv.innerHTML = `
                        <h1>${user.name}</h1>
                        <p>${user.bio}</p>
                        <span>${user.email}</span>
                    `;
                }
            });
    }

    // VULNERABILITY: CWE-79 - XSS via outerHTML (Line 50)
    replaceElement(element: HTMLElement, html: string): void {
        element.outerHTML = html;
    }

    // VULNERABILITY: CWE-79 - XSS via insertAdjacentHTML (Line 55)
    appendContent(content: string): void {
        const container = document.getElementById('profile-container');
        if (container) {
            container.insertAdjacentHTML('beforeend', content);
        }
    }

    // Safe example - Text content (NOT a vulnerability)
    setTextSafe(text: string): void {
        const element = document.getElementById('safe-element');
        if (element) {
            element.textContent = text;  // Safe - escapes HTML
        }
    }
}
