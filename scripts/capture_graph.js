const puppeteer = require('puppeteer');

(async () => {
    const browser = await puppeteer.launch();
    const page = await browser.newPage();
    await page.goto('http://localhost:8000/graph/', { waitUntil: 'networkidle2' });
    await page.setViewport({ width: 800, height: 600 });
    await page.screenshot({ path: 'static/images/graph.png' });
    await browser.close();
})();
