document.addEventListener("DOMContentLoaded", function () {
    // Esperar a que todo el contenido se cargue
    setTimeout(() => {
        // Inicializar Select2 en todos los <select> con soporte para Django Admin
        $('select').select2({
            width: '100%',
            theme: 'default'
        });

        console.log("✅ Select2 inicializado correctamente.");
    }, 500); // Pequeño delay para asegurarse de que todo está cargado
});