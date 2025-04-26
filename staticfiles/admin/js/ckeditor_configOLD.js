document.addEventListener("DOMContentLoaded", function () {
    ClassicEditor
        .create(document.querySelector('.django-ckeditor-widget'), {
            fontColor: {
                colors: [
                    { color: 'rgb(0, 0, 0)', label: 'Negro' }, // 🔹 Negro por defecto
                    { color: 'rgb(255, 0, 0)', label: 'Rojo' },
                    { color: 'rgb(0, 255, 0)', label: 'Verde' },
                    { color: 'rgb(0, 0, 255)', label: 'Azul' }
                ],
                columns: 5
            },
            fontBackgroundColor: {
                colors: [
                    { color: 'rgb(255, 255, 0)', label: 'Amarillo' },
                    { color: 'rgb(0, 255, 0)', label: 'Verde' },
                    { color: 'rgb(0, 0, 255)', label: 'Azul' }
                ],
                columns: 5
            }
        })
        .then(editor => {
            editor.editing.view.change(writer => {
                writer.setStyle('color', 'black', editor.editing.view.document.getRoot());  // 🔹 🔥 Forzar negro por defecto
            });
        })
        .catch(error => {
            console.error(error);
        });
});