// Definimos la función para insertar el marcador de posición fuera de la función tinymce.init
function insertPlaceholderImage() {
    var placeholderHTML = '<img src="/static/img/image-placeholder.jpg" id="placeholder_vulnerabilities" alt="Overall Vulnerabilities Placeholder">';
    tinymce.activeEditor.execCommand('mceInsertContent', false, placeholderHTML);
}

// Configuración y activación de TinyMCE
tinymce.init({
    selector: '#editor',
    plugins: 'image',
    toolbar: 'undo redo | link image | placeholder_button', // Agregamos el botón placeholder_button al toolbar
    setup: function(editor) {
        // Registramos el botón en el editor
        editor.ui.registry.addButton('placeholder_button', {
            text: 'Insertar Marcador de Posición',
            onAction: function() {
                insertPlaceholderImage();
            }
        });
    }
});

