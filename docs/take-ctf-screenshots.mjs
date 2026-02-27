#!/usr/bin/env node
// Screenshot capture for the CTF / Vulnerable app pages
import puppeteer from 'puppeteer';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DIR = join(__dirname, 'screenshots');
const BASE = 'http://92.5.23.86';
const delay = ms => new Promise(r => setTimeout(r, ms));

async function main() {
  const browser = await puppeteer.launch({
    headless: 'shell',
    args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-web-security']
  });
  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36');
  await page.setViewport({ width: 1440, height: 900 });

  // 1. CTF Challenges tab
  console.log('Capturing CTF challenges...');
  await page.goto(`${BASE}/vulnerable`, { waitUntil: 'networkidle2', timeout: 30000 });
  await delay(500);
  await page.screenshot({ path: join(DIR, 'ctf-01-challenges.png') });
  console.log('  Done');

  // 2. Scroll to GOAD section
  console.log('Capturing GOAD section...');
  await page.evaluate(() => {
    const headers = document.querySelectorAll('.section-header');
    for (const h of headers) {
      if (h.textContent.includes('GOAD')) { h.scrollIntoView({ behavior: 'instant' }); break; }
    }
  });
  await delay(300);
  await page.screenshot({ path: join(DIR, 'ctf-02-goad.png') });
  console.log('  Done');

  // 3. Click an attack and show response
  console.log('Capturing challenge response...');
  await page.evaluate(() => window.scrollTo(0, 0));
  await delay(200);
  await page.evaluate(() => {
    const firstCard = document.querySelector('.challenge-card');
    if (firstCard) firstCard.click();
  });
  await delay(2000);
  await page.evaluate(() => {
    const panel = document.getElementById('response-panel');
    if (panel) panel.scrollIntoView({ behavior: 'instant' });
  });
  await delay(300);
  await page.screenshot({ path: join(DIR, 'ctf-03-response.png') });
  console.log('  Done');

  // 4. Walkthrough tab
  console.log('Capturing walkthrough...');
  await page.evaluate(() => {
    const links = document.querySelectorAll('.nav-links a');
    for (const l of links) {
      if (l.dataset.tab === 'walkthrough') { l.click(); break; }
    }
  });
  await delay(500);
  await page.screenshot({ path: join(DIR, 'ctf-04-walkthrough.png') });
  console.log('  Done');

  // 5. Expand first walkthrough
  console.log('Capturing expanded walkthrough...');
  await page.evaluate(() => {
    const header = document.querySelector('.guide-header');
    if (header) header.click();
  });
  await delay(300);
  await page.screenshot({ path: join(DIR, 'ctf-05-walkthrough-expanded.png') });
  console.log('  Done');

  // 6. Full page screenshot
  console.log('Capturing full page...');
  await page.evaluate(() => {
    const links = document.querySelectorAll('.nav-links a');
    for (const l of links) {
      if (l.dataset.tab === 'challenges') { l.click(); break; }
    }
  });
  await delay(500);
  await page.screenshot({ path: join(DIR, 'ctf-00-full.png'), fullPage: true });
  console.log('  Done');

  await browser.close();
  console.log('\nAll CTF screenshots saved.');
}

main().catch(err => { console.error('Error:', err.message); process.exit(1); });
