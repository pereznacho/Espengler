document.addEventListener("DOMContentLoaded", function () {
    var configElement = document.getElementById("ckeditor-config");
    var configUrl = configElement ? configElement.getAttribute("data-config-url") : "";

    if (typeof CKEDITOR !== "undefined") {
        CKEDITOR.replace("editor_id", {
            customConfig: configUrl,
            contentsCss: "/static/css/custom.css", // Carga tu CSS personalizado
            bodyClass: "editor-content", // Aplica la clase CSS para el editor
            font_defaultLabel: "Arial",
            fontSize_defaultLabel: "16px",
            colorButton_foreStyle: {
                element: "span",
                styles: { color: "#000000" } // Texto en negro
            },
        });

        CKEDITOR.on("instanceReady", function (event) {
            var editor = event.editor;

            // Verifica si el CSS está aplicado
            console.log("CSS en CKEditor:", editor.config.contentsCss);

            // Forzar la carga manual del CSS si es necesario
            try {
                if (editor.document) {
                    editor.document.appendStyleSheet("/static/css/custom.css");
                } else {
                    console.error("No se pudo acceder al documento de CKEditor.");
                }
            } catch (error) {
                console.error("Error al aplicar el CSS en CKEditor:", error);
            }
        });
    } else {
        console.error("CKEditor no se cargó correctamente.");
    }
});