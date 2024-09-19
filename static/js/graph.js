import { ForceSimulation } from '@livereader/graphly-d3';

document.addEventListener('DOMContentLoaded', function() {
    const svg = document.getElementById('mySVG');
    fetch('/graph_view/')  // Asegúrate de que esta URL apunte a tu vista de datos
        .then(response => response.json())
        .then(data => {
            const simulation = new ForceSimulation(svg);
            simulation.render(data);
        });
});
