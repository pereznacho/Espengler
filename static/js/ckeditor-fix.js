document.addEventListener("DOMContentLoaded", function () {
    // 🔁 Estilos oscuros para el editor
    function applyCKEditorStyles() {
        setTimeout(function () {
            let ckEditors = document.querySelectorAll(".ck.ck-editor__editable");

            ckEditors.forEach(editor => {
                if (editor) {
                    editor.style.backgroundColor = "#3f474e";
                    editor.style.color = "#ffffff";
                    editor.style.padding = "10px";
                    editor.style.borderRadius = "5px";
                }
            });

            let iframes = document.querySelectorAll("iframe");

            iframes.forEach(iframe => {
                iframe.onload = function () {
                    let iframeDocument = iframe.contentDocument || iframe.contentWindow.document;
                    if (iframeDocument) {
                        let style = iframeDocument.createElement("style");
                        style.innerHTML = `
                            body {
                                background-color: #3f474e !important;
                                color: #ffffff !important;
                            }
                            p {
                                color: #ffffff !important;
                            }
                        `;
                        iframeDocument.head.appendChild(style);
                    }
                };
            });
        }, 1000);
    }

    // ✅ Adaptador personalizado de subida
    class MyUploadAdapter {
        constructor(loader) {
            this.loader = loader;
        }

        upload() {
            return this.loader.file.then(file => {
                return new Promise((resolve, reject) => {
                    const data = new FormData();
                    data.append('upload', file);

                    const writeupTitle = document.querySelector('#id_title')?.value || 'temp';
                    data.append('writeup_title', writeupTitle);

                    fetch('/upload-image/', {
                        method: 'POST',
                        body: data,
                        headers: {
                            'X-CSRFToken': getCookie('csrftoken')
                        }
                    })
                    .then(response => response.json())
                    .then(result => {
                        console.log("✅ Imagen subida correctamente:", result.url);
                        resolve({ default: result.url });
                    })
                    .catch(err => {
                        console.error("❌ Error al subir la imagen:", err);
                        reject(err);
                    });
                });
            });
        }

        abort() {}
    }

    // ✅ Obtener el token CSRF
    function getCookie(name) {
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let cookie of cookies) {
                cookie = cookie.trim();
                if (cookie.startsWith(name + '=')) {
                    cookieValue = decodeURIComponent(cookie.slice(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    // 🔁 Esperar a que CKEditor se haya inicializado automáticamente por Django
    const interval = setInterval(() => {
        const ck = document.querySelector('.ck.ck-editor__editable');

        // Ya fue montado el editor
        if (ck && ck.ckeditorInstance) {
            const editor = ck.ckeditorInstance;

            // Reemplazar el UploadAdapter
            editor.plugins.get('FileRepository').createUploadAdapter = (loader) => {
                return new MyUploadAdapter(loader);
            };

            console.log("✅ UploadAdapter personalizado inyectado");
            applyCKEditorStyles();
            clearInterval(interval);
        }
    }, 300);  // Verifica cada 300ms hasta que lo encuentra

    // También aplicar estilos en eventos de interacción
    document.addEventListener("click", function (event) {
        if (event.target.closest(".ck-toolbar") || event.target.closest(".ck")) {
            applyCKEditorStyles();
        }
    });
});