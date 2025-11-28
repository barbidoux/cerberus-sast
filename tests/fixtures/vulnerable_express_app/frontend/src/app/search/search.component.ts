/**
 * Search Component - Contains DOM XSS vulnerabilities
 */

import { Component, OnInit, ElementRef, ViewChild } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';

@Component({
    selector: 'app-search',
    template: `
        <div class="search-container">
            <input [(ngModel)]="searchQuery" (keyup.enter)="search()">
            <button (click)="search()">Search</button>
            <div #resultsContainer></div>
            <div [innerHTML]="resultsHtml"></div>
        </div>
    `
})
export class SearchComponent implements OnInit {
    searchQuery: string = '';
    resultsHtml: string = '';

    @ViewChild('resultsContainer') resultsContainer!: ElementRef;

    constructor(
        private route: ActivatedRoute,
        private sanitizer: DomSanitizer
    ) {}

    ngOnInit(): void {
        // VULNERABILITY: CWE-79 - XSS via URL query parameter (Line 33)
        this.route.queryParams.subscribe(params => {
            if (params['q']) {
                this.searchQuery = params['q'];
                this.displayResults(`Searching for: ${params['q']}`);
            }
        });
    }

    // VULNERABILITY: CWE-79 - DOM XSS via innerHTML (Line 42)
    displayResults(html: string): void {
        this.resultsContainer.nativeElement.innerHTML = html;
    }

    // VULNERABILITY: CWE-79 - XSS via template binding (Line 47)
    search(): void {
        // User input directly rendered as HTML
        this.resultsHtml = `<div class="results"><h2>Results for: ${this.searchQuery}</h2></div>`;
    }

    // VULNERABILITY: CWE-79 - XSS via document.write (Line 53)
    legacyRender(content: string): void {
        document.write(`<html><body>${content}</body></html>`);
    }

    // VULNERABILITY: CWE-94 - Code Injection via eval (Line 58)
    executeScript(userScript: string): void {
        eval(userScript);
    }

    // VULNERABILITY: CWE-94 - Code Injection via Function constructor (Line 63)
    dynamicFunction(code: string): any {
        const fn = new Function('data', code);
        return fn;
    }
}
