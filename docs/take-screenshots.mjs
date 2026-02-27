#!/usr/bin/env node
// Screenshot capture script for Seven Kingdoms Portal documentation
import puppeteer from 'puppeteer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const SCREENSHOTS_DIR = join(__dirname, 'screenshots');
const BASE_URL = 'http://92.5.23.86';

const delay = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  const browser = await puppeteer.launch({
    headless: 'shell',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-web-security',
      '--disable-features=IsolateOrigins,site-per-process'
    ]
  });

  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
  await page.setViewport({ width: 1440, height: 900 });

  // 1. Login page
  console.log('Capturing login page...');
  await page.goto(`${BASE_URL}/portal/`, { waitUntil: 'networkidle2', timeout: 30000 });

  // Capture login screen first
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '01-login.png'), fullPage: false });
  console.log('  Login page captured');

  // Clear fields and login with admin/admin
  await page.evaluate(() => {
    document.getElementById('login-user').value = '';
    document.getElementById('login-pass').value = '';
  });
  await page.type('#login-user', 'admin');
  await page.type('#login-pass', 'admin');
  // Find and click the Sign In button
  await page.evaluate(() => {
    const btns = document.querySelectorAll('button');
    for (const b of btns) {
      if (b.textContent.includes('Sign In')) { b.click(); return; }
    }
  });
  await delay(2000);

  // Verify we logged in by checking if app-view is visible
  const loggedIn = await page.evaluate(() => {
    const appView = document.getElementById('app-view');
    return appView && appView.style.display !== 'none';
  });
  console.log('  Logged in:', loggedIn);

  if (!loggedIn) {
    // Try via direct API login
    console.log('  Trying API login...');
    await page.evaluate(async () => {
      const resp = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'admin' })
      });
      const data = await resp.json();
      if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('username', 'admin');
        localStorage.setItem('role', 'superadmin');
      }
    });
    await page.reload({ waitUntil: 'networkidle2' });
    await delay(1500);

    // Click login again after reload
    const stillOnLogin = await page.evaluate(() => {
      const loginSection = document.getElementById('login-view');
      return loginSection && loginSection.style.display !== 'none';
    });
    if (stillOnLogin) {
      await page.evaluate(() => {
        document.getElementById('login-user').value = '';
        document.getElementById('login-pass').value = '';
      });
      await page.type('#login-user', 'admin');
      await page.type('#login-pass', 'admin');
      await page.evaluate(() => {
        const btns = document.querySelectorAll('button');
        for (const b of btns) {
          if (b.textContent.includes('Sign In')) { b.click(); return; }
        }
      });
      await delay(2000);
    }
  }

  // 2. Dashboard
  console.log('Capturing dashboard...');
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '02-dashboard.png'), fullPage: false });
  console.log('  Dashboard captured');

  // Debug: check what's visible
  const pageState = await page.evaluate(() => {
    return {
      title: document.title,
      loginVisible: document.getElementById('login-view')?.style.display,
      appVisible: document.getElementById('app-view')?.style.display,
      tabs: Array.from(document.querySelectorAll('.nav-tabs a')).map(a => a.textContent)
    };
  });
  console.log('  Page state:', JSON.stringify(pageState));

  // 3. Dashboard - scroll to attack runner
  console.log('Capturing attack runner...');
  await page.evaluate(() => {
    const el = document.querySelector('.attack-runner');
    if (el) el.scrollIntoView({ behavior: 'instant' });
  });
  await delay(300);
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '03-attack-runner.png'), fullPage: false });
  console.log('  Attack runner captured');

  await page.evaluate(() => window.scrollTo(0, 0));
  await delay(200);

  // Helper to switch tabs
  async function switchTab(tabName, filename, label) {
    console.log(`Capturing ${label}...`);
    await page.evaluate((tab) => {
      const link = document.querySelector(`[data-tab="${tab}"]`);
      if (link) link.click();
    }, tabName);
    await delay(800);
    await page.screenshot({ path: join(SCREENSHOTS_DIR, filename), fullPage: false });
    console.log(`  ${label} captured`);
  }

  // 4-6. Other tabs
  await switchTab('treasury', '04-treasury.png', 'Treasury');
  await switchTab('attacks', '05-attacks.png', 'Attacks');
  await switchTab('goad', '06-goad-lab.png', 'GOAD Lab');

  // 7. Learn tab (Attack Encyclopedia)
  await switchTab('learn', '07-learn-overview.png', 'Learn overview');

  // 8. Expand first category (A01)
  console.log('Capturing A01 expanded...');
  await page.evaluate(() => {
    const headers = document.querySelectorAll('.enc-category-header');
    if (headers.length > 0) headers[0].click();
  });
  await delay(500);
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '08-learn-a01-category.png'), fullPage: false });
  console.log('  A01 category captured');

  // 9. Expand first attack detail
  console.log('Capturing attack detail...');
  await page.evaluate(() => {
    const headers = document.querySelectorAll('.enc-attack-header');
    if (headers.length > 0) headers[0].click();
  });
  await delay(500);
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '09-learn-attack-detail.png'), fullPage: false });
  console.log('  Attack detail captured');

  // 10. Scroll to detection queries
  console.log('Capturing detection queries...');
  await page.evaluate(() => {
    const grid = document.querySelector('.enc-detection-grid');
    if (grid) grid.scrollIntoView({ behavior: 'instant', block: 'center' });
  });
  await delay(300);
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '10-learn-detection-queries.png'), fullPage: false });
  console.log('  Detection queries captured');

  // 11. Detections tab
  await page.evaluate(() => window.scrollTo(0, 0));
  await switchTab('detections', '11-detections.png', 'Detections');

  // 12. CTF Board
  await switchTab('ctf', '12-ctf-board.png', 'CTF Board');

  // 13. Full-page dashboard
  console.log('Capturing full-page dashboard...');
  await page.evaluate(() => {
    const link = document.querySelector('[data-tab="dashboard"]');
    if (link) link.click();
  });
  await delay(500);
  await page.screenshot({ path: join(SCREENSHOTS_DIR, '00-dashboard-full.png'), fullPage: true });
  console.log('  Full-page dashboard captured');

  await browser.close();
  console.log('\nAll screenshots saved to docs/screenshots/');
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
