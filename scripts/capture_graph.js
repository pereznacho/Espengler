const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// 📌 Capturar argumentos desde Django
const args = process.argv.slice(2);
const projectId = args[0];
const sessionCookie = args[1] || null;
const csrfToken = args[2] || null;

// 📌 Validar que se pasaron los valores correctos
if (!projectId || !sessionCookie) {
    console.error("❌ ERROR: Se requiere el ID del proyecto y la cookie de sesión.");
    process.exit(1);
}

// 📌 Rutas y configuraciones
const IMAGE_PATH = path.join(__dirname, '../static/images', `graphmap_project_${projectId}.png`);
const GRAPHMAP_URL = `http://localhost:8000/project/${projectId}/graph_map/`;

(async () => {
    try {
        console.log(`🔄 Abriendo navegador para capturar GraphMap de Project ${projectId}...`);

        // ✅ Lanzar navegador
        const browser = await puppeteer.launch({
            executablePath: '/usr/bin/chromium', // Asegúrate de que Chromium esté instalado
            headless: true,
            args: ['--no-sandbox', '--disable-setuid-sandbox']
        });

        const page = await browser.newPage();

        // 📌 Configurar cookies de sesión en Puppeteer
        const djangoCookies = [
            {
                name: 'sessionid',
                value: sessionCookie,
                domain: 'localhost',  // ⚠️ Cambia esto en producción
                path: '/',
                httpOnly: true
            }
        ];

        if (csrfToken) {
            djangoCookies.push({
                name: 'csrftoken',
                value: csrfToken,
                domain: 'localhost',
                path: '/',
                httpOnly: false
            });
        }

        await page.setCookie(...djangoCookies);
        console.log("✅ Cookies de sesión configuradas en Puppeteer.");

        // 📌 Acceder a GraphMap
        console.log(`📌 Navegando a GraphMap del Proyecto ${projectId}...`);
        await page.goto(GRAPHMAP_URL + '?embed=1', { waitUntil: 'networkidle2' });

        console.log("⌛ Esperando que el contenedor de GraphMap cargue...");
        await page.waitForSelector("#graph-container", { timeout: 60000 });

        console.log("🔄 Esperando que GraphMap tenga nodos...");
        let nodesLoaded = false;
        let attempts = 0;
        const maxAttempts = 10;

        while (!nodesLoaded && attempts < maxAttempts) {
            nodesLoaded = await page.evaluate(() => {
                const images = document.querySelectorAll("#graph-container canvas");
                // Vis.js uses canvas, so we check for canvas or valid network instance
                return !!document.querySelector("#graph-container canvas");
            });

            if (nodesLoaded) {
                console.log("✅ Nodos y enlaces de GraphMap detectados, listo para capturar.");
                break;
            }

            console.log(`🔄 Intento ${attempts + 1}: Forzando actualización de GraphMap...`);
            await page.evaluate(() => {
                if (window.updateGraph) {
                    window.updateGraph();
                }
            });

            await new Promise(resolve => setTimeout(resolve, 5000));
            attempts++;
        }

        if (!nodesLoaded) {
            throw new Error("❌ Los nodos del GraphMap no se renderizaron correctamente.");
        }

        console.log("📸 Capturando imagen del contenedor GraphMap...");
        const graphMapContainer = await page.$("#graph-container");
        if (graphMapContainer) {
            await graphMapContainer.screenshot({ path: IMAGE_PATH });
            console.log(`✅ Imagen guardada en: ${IMAGE_PATH}`);
        } else {
            throw new Error("No se encontró el contenedor de GraphMap.");
        }

        await browser.close();
        process.exit(0);
    } catch (error) {
        console.error(`❌ ERROR en Puppeteer: ${error.message}`);
        process.exit(1);
    }
})();
