import { spawn } from 'child_process';
import { promisify } from 'util';
import { exec } from 'child_process';
import dns from 'dns';
import net from 'net';
import https from 'https';
import http from 'http';

const execAsync = promisify(exec);

export interface ReconResults {
  target: string;
  subdomains: string[];
  openPorts: number[];
  technologies: { name: string; version?: string; category: string }[];
  dnsRecords: { type: string; value: string }[];
  whoisData?: any;
  headers: { [key: string]: string };
  statusCode?: number;
  certificates?: any;
}

export class ReconnaissanceService {
  private validateTarget(target: string): boolean {
    // Basic domain/IP validation
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    
    return domainRegex.test(target) || ipRegex.test(target);
  }

  async performReconnaissance(target: string): Promise<ReconResults> {
    if (!this.validateTarget(target)) {
      throw new Error('Invalid target format');
    }

    const results: ReconResults = {
      target,
      subdomains: [],
      openPorts: [],
      technologies: [],
      dnsRecords: [],
      headers: {},
    };

    try {
      // Run reconnaissance tasks in parallel
      const [subdomains, openPorts, dnsRecords, webInfo, whoisData] = await Promise.allSettled([
        this.enumerateSubdomains(target),
        this.scanPorts(target),
        this.getDNSRecords(target),
        this.getWebInfo(target),
        this.getWhoisData(target),
      ]);

      if (subdomains.status === 'fulfilled') {
        results.subdomains = subdomains.value;
      }

      if (openPorts.status === 'fulfilled') {
        results.openPorts = openPorts.value;
      }

      if (dnsRecords.status === 'fulfilled') {
        results.dnsRecords = dnsRecords.value;
      }

      if (webInfo.status === 'fulfilled') {
        results.headers = webInfo.value.headers;
        results.statusCode = webInfo.value.statusCode;
        results.technologies = webInfo.value.technologies;
        results.certificates = webInfo.value.certificates;
      }

      if (whoisData.status === 'fulfilled') {
        results.whoisData = whoisData.value;
      }

    } catch (error) {
      console.error('Reconnaissance error:', error);
      throw new Error('Failed to perform reconnaissance');
    }

    return results;
  }

  private async enumerateSubdomains(target: string): Promise<string[]> {
    const subdomains: string[] = [];
    
    try {
      // Common subdomain list
      const commonSubdomains = [
        'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 
        'blog', 'shop', 'secure', 'vpn', 'remote', 'support', 'help',
        'cdn', 'static', 'media', 'assets', 'images', 'video', 'app',
        'mobile', 'beta', 'alpha', 'demo', 'portal', 'dashboard'
      ];

      // Test each subdomain
      for (const sub of commonSubdomains) {
        const subdomain = `${sub}.${target}`;
        try {
          await this.resolveDNS(subdomain);
          subdomains.push(subdomain);
        } catch (error) {
          // Subdomain doesn't exist, continue
        }
      }

    } catch (error) {
      console.error('Subdomain enumeration error:', error);
    }

    return subdomains;
  }

  private async resolveDNS(hostname: string): Promise<void> {
    return new Promise((resolve, reject) => {
      dns.lookup(hostname, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  private async scanPorts(target: string): Promise<number[]> {
    const openPorts: number[] = [];
    const commonPorts = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443, 3000, 3306, 5432, 6379, 27017];

    const portPromises = commonPorts.map(port => this.checkPort(target, port));
    const results = await Promise.allSettled(portPromises);

    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        openPorts.push(commonPorts[index]);
      }
    });

    return openPorts;
  }

  private async checkPort(target: string, port: number): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const timeout = 3000;

      socket.setTimeout(timeout);
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });

      socket.on('error', () => {
        resolve(false);
      });

      socket.connect(port, target);
    });
  }

  private async getDNSRecords(target: string): Promise<{ type: string; value: string }[]> {
    const records: { type: string; value: string }[] = [];

    try {
      // A records
      const aRecords = await this.getDNSRecord(target, 'A');
      aRecords.forEach(record => records.push({ type: 'A', value: record }));

      // AAAA records
      const aaaaRecords = await this.getDNSRecord(target, 'AAAA');
      aaaaRecords.forEach(record => records.push({ type: 'AAAA', value: record }));

      // MX records
      const mxRecords = await this.getDNSRecord(target, 'MX');
      mxRecords.forEach(record => records.push({ type: 'MX', value: record }));

      // TXT records
      const txtRecords = await this.getDNSRecord(target, 'TXT');
      txtRecords.forEach(record => records.push({ type: 'TXT', value: record }));

      // NS records
      const nsRecords = await this.getDNSRecord(target, 'NS');
      nsRecords.forEach(record => records.push({ type: 'NS', value: record }));

    } catch (error) {
      console.error('DNS lookup error:', error);
    }

    return records;
  }

  private async getDNSRecord(target: string, type: string): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const records: string[] = [];

      switch (type) {
        case 'A':
          dns.resolve4(target, (err, addresses) => {
            if (err) reject(err);
            else resolve(addresses);
          });
          break;
        case 'AAAA':
          dns.resolve6(target, (err, addresses) => {
            if (err) reject(err);
            else resolve(addresses);
          });
          break;
        case 'MX':
          dns.resolveMx(target, (err, addresses) => {
            if (err) reject(err);
            else resolve(addresses.map(mx => `${mx.priority} ${mx.exchange}`));
          });
          break;
        case 'TXT':
          dns.resolveTxt(target, (err, addresses) => {
            if (err) reject(err);
            else resolve(addresses.map(txt => txt.join('')));
          });
          break;
        case 'NS':
          dns.resolveNs(target, (err, addresses) => {
            if (err) reject(err);
            else resolve(addresses);
          });
          break;
        default:
          reject(new Error(`Unsupported DNS record type: ${type}`));
      }
    });
  }

  private async getWebInfo(target: string): Promise<{
    headers: { [key: string]: string };
    statusCode: number;
    technologies: { name: string; version?: string; category: string }[];
    certificates?: any;
  }> {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: target,
        port: 443,
        path: '/',
        method: 'GET',
        timeout: 10000,
        rejectUnauthorized: false,
      };

      const req = https.request(options, (res) => {
        const headers = res.headers as { [key: string]: string };
        const statusCode = res.statusCode || 0;
        const technologies = this.detectTechnologies(headers);
        const certificates = (res.socket as any).getPeerCertificate?.();

        resolve({
          headers,
          statusCode,
          technologies,
          certificates,
        });
      });

      req.on('error', (error) => {
        // Try HTTP if HTTPS fails
        const httpOptions = { ...options, port: 80 };
        const httpReq = http.request(httpOptions, (res) => {
          const headers = res.headers as { [key: string]: string };
          const statusCode = res.statusCode || 0;
          const technologies = this.detectTechnologies(headers);

          resolve({
            headers,
            statusCode,
            technologies,
          });
        });

        httpReq.on('error', reject);
        httpReq.setTimeout(10000, () => httpReq.abort());
        httpReq.end();
      });

      req.setTimeout(10000, () => req.abort());
      req.end();
    });
  }

  private detectTechnologies(headers: { [key: string]: string }): { name: string; version?: string; category: string }[] {
    const technologies: { name: string; version?: string; category: string }[] = [];

    // Server detection
    if (headers.server) {
      const server = headers.server.toLowerCase();
      if (server.includes('apache')) {
        const version = server.match(/apache\/([^\s]+)/)?.[1];
        technologies.push({ name: 'Apache', version, category: 'web_server' });
      } else if (server.includes('nginx')) {
        const version = server.match(/nginx\/([^\s]+)/)?.[1];
        technologies.push({ name: 'Nginx', version, category: 'web_server' });
      } else if (server.includes('iis')) {
        const version = server.match(/iis\/([^\s]+)/)?.[1];
        technologies.push({ name: 'IIS', version, category: 'web_server' });
      }
    }

    // Framework detection
    if (headers['x-powered-by']) {
      const poweredBy = headers['x-powered-by'].toLowerCase();
      if (poweredBy.includes('php')) {
        const version = poweredBy.match(/php\/([^\s]+)/)?.[1];
        technologies.push({ name: 'PHP', version, category: 'framework' });
      } else if (poweredBy.includes('asp.net')) {
        technologies.push({ name: 'ASP.NET', category: 'framework' });
      }
    }

    // Content Management System detection
    if (headers['x-generator']) {
      const generator = headers['x-generator'].toLowerCase();
      if (generator.includes('wordpress')) {
        technologies.push({ name: 'WordPress', category: 'cms' });
      } else if (generator.includes('drupal')) {
        technologies.push({ name: 'Drupal', category: 'cms' });
      }
    }

    return technologies;
  }

  private async getWhoisData(target: string): Promise<any> {
    try {
      const { stdout } = await execAsync(`whois ${target}`);
      return this.parseWhoisData(stdout);
    } catch (error) {
      console.error('Whois lookup error:', error);
      return null;
    }
  }

  private parseWhoisData(whoisOutput: string): any {
    const lines = whoisOutput.split('\n');
    const data: any = {};

    lines.forEach(line => {
      const [key, ...valueParts] = line.split(':');
      if (key && valueParts.length > 0) {
        const value = valueParts.join(':').trim();
        if (value) {
          data[key.trim().toLowerCase()] = value;
        }
      }
    });

    return data;
  }
}
