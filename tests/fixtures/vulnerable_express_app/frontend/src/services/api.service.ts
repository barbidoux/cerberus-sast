/**
 * API Service - Contains SSRF vulnerabilities
 */

import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable({
    providedIn: 'root'
})
export class ApiService {
    constructor(private http: HttpClient) {}

    // VULNERABILITY: CWE-918 - SSRF via user-controlled URL (Line 17)
    fetchExternalData(userUrl: string): Observable<any> {
        return this.http.get(userUrl);
    }

    // VULNERABILITY: CWE-918 - SSRF via user-controlled endpoint (Line 22)
    proxyRequest(targetUrl: string, method: string = 'GET'): Observable<any> {
        if (method === 'GET') {
            return this.http.get(targetUrl);
        } else {
            return this.http.post(targetUrl, {});
        }
    }

    // VULNERABILITY: CWE-918 - SSRF via template string (Line 31)
    fetchUserAvatar(userId: string, imageServer: string): Observable<Blob> {
        const url = `${imageServer}/avatars/${userId}.png`;
        return this.http.get(url, { responseType: 'blob' });
    }

    // VULNERABILITY: CWE-918 - SSRF via webhook URL (Line 37)
    sendWebhook(webhookUrl: string, payload: any): Observable<any> {
        return this.http.post(webhookUrl, payload);
    }

    // VULNERABILITY: CWE-918 - SSRF via redirect following (Line 42)
    fetchWithRedirect(url: string): Observable<any> {
        return this.http.get(url, {
            headers: { 'X-Follow-Redirects': 'true' }
        });
    }

    // Safe example - Fixed base URL (NOT a vulnerability)
    getUsers(): Observable<any[]> {
        return this.http.get<any[]>('/api/users');  // Fixed path, not user-controlled
    }

    // Safe example - User ID only, not URL (NOT a vulnerability)
    getUserById(userId: string): Observable<any> {
        return this.http.get<any>(`/api/users/${encodeURIComponent(userId)}`);
    }
}
