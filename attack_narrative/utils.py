import markdown
import os
import re

def import_obsidian_note(file_path):
    """
    Convierte una nota Obsidian (.md) en HTML legible para CKEditor5 y mantiene los metadatos.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content_md = file.read()

        # Extraer metadatos del inicio del archivo
        metadata = {}
        raw_metadata = []
        body = []
        parsing_metadata = True

        for line in content_md.splitlines():
            if parsing_metadata:
                match = re.match(r"^([\w\s]+):\s*(.+)$", line)
                if match:
                    key, value = match.groups()
                    metadata[key.strip().lower().replace(" ", "_")] = value.strip()
                    raw_metadata.append(line.strip())  # Guardar metadatos originales
                elif line.strip() == "":
                    parsing_metadata = False  # Fin de metadatos
                else:
                    parsing_metadata = False
                    body.append(line.strip())  # Agregar la primera línea de contenido real
            else:
                body.append(line.strip())

        # Unir los metadatos como texto formateado en Markdown
        metadata_text = "\n".join(raw_metadata)

        # Unir contenido principal
        body_content = "\n".join(body)

        # Concatenar metadatos + contenido antes de convertir a HTML
        full_markdown = f"{metadata_text}\n\n{body_content}"

        # 🔹 Convertir Markdown a HTML con soporte de estilos avanzados
        content_html = markdown.markdown(
            full_markdown,
            extensions=[
                "extra", "fenced_code", "codehilite", "tables", "nl2br",
                "sane_lists", "footnotes", "attr_list", "md_in_html"
            ]
        )

        # Determinar el título (prioridad: metadatos > nombre del archivo)
        title = metadata.get("title", os.path.basename(file_path).replace(".md", ""))

        return {
            "title": title,
            "content_html": content_html
        }

    except Exception as e:
        print(f"Error al procesar el archivo Obsidian: {e}")
        return {}