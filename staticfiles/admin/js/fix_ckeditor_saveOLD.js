document.addEventListener("DOMContentLoaded", function () {
    let form = document.querySelector("form");
    if (form) {
        form.addEventListener("submit", function () {
            let editorInstance = document.querySelector("[name=content_html]");
            if (editorInstance && window.editor) {
                editorInstance.value = window.editor.getData();
            }
        });
    }
});