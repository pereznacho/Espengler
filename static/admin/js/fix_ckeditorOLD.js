document.addEventListener("DOMContentLoaded", function () {
    document.querySelector("form").addEventListener("submit", function () {
        if (window.editor) {
            document.querySelector("[name=content_html]").value = window.editor.getData();
        }
    });
});