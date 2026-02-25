# Logos del GraphMap (sistemas operativos)

Iconos mostrados en el **mapa de ataque** (GraphMap) para identificar el sistema operativo de cada objetivo.

---

## Windows (logos oficiales)

Los iconos de cada versión de Windows se **descargan automáticamente** al ejecutar el script de logos. Proceden de **Wikimedia Commons**, donde están documentados como logos de Microsoft (Windows 8/10: símbolo 2012; Windows 11: símbolo 2021).

### Descarga automática

Al ejecutar el script se descargan los SVG de Windows desde Commons. Opcional: [Microsoft Brand Assets](https://partner.microsoft.com/en-us/marketing-center/brand-assets)  
Tabla de archivos descargados:

| Archivo | Origen (Commons) |
|--------|-------------------|
| `windows.svg` | Windows logo 2021 |
| `windows_xp.svg`, `windows_vista.svg`, `windows_7.svg` | Windows logo 2012 |
| `windows_8.svg`, `windows_10.svg`, `windows_server.svg` | Windows logo 2012 |
| `windows_11.svg`, `windows_12.svg` | Windows logo 2021 |

---

## Otros sistemas (Simple Icons)

Los SVG del resto de sistemas se obtienen de **[Simple Icons](https://simpleicons.org)** (licencia **CC0-1.0**), conjunto de iconos de marcas mantenido por la comunidad.

- **Web:** https://simpleicons.org  
- **CDN:** `https://cdn.simpleicons.org/{slug}/{color}`  

### Cómo descargar (no-Windows)

Desde la **raíz del proyecto**:

```bash
python3 scripts/download_graphmap_logos.py
```

Esto descarga en esta carpeta los logos de Linux, Ubuntu, Debian, Kali, etc. y **también** los de cada versión de Windows (desde Wikimedia Commons).

### Archivos esperados (no-Windows)

| Archivo | Sistema / marca |
|--------|------------------|
| `linux.svg` | Linux (Tux) |
| `ubuntu.svg` | Ubuntu |
| `debian.svg` | Debian |
| `kali.svg` | Kali Linux |
| `arch.svg` | Arch Linux |
| `fedora.svg` | Fedora |
| `redhat.svg` | Red Hat |
| `macos.svg` | Apple / macOS |
| `android.svg` | Android |
| `unknown.svg` | Placeholder (OS desconocido) |

---

## Uso en el mapa

El **mapa de ataque usa solo los SVG** de esta carpeta (no PNG autogenerados). Los nodos cargan los iconos en formato SVG directamente. La vista que genera la imagen “imac + logo” (cuando se pide la imagen del nodo) usa también los SVG y, si está disponible **cairosvg**, los convierte a imagen en el servidor. No es necesario ejecutar `generate_graphmap_pngs.py` para el mapa.
