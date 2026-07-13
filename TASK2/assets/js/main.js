document.addEventListener("DOMContentLoaded", () => {
    const hotspots = document.querySelectorAll('.hotspot');

    hotspots.forEach(hotspot => {
        hotspot.addEventListener('click', (e) => {
            // Empêche la propagation du clic pour éviter de fermer immédiatement
            e.stopPropagation(); 
            
            // Si le point cliqué est déjà actif, on le ferme, sinon on l'ouvre
            const isActive = hotspot.classList.contains('active');
            
            // Fermer tous les autres points ouverts
            hotspots.forEach(h => h.classList.remove('active'));
            
            if (!isActive) {
                hotspot.classList.add('active');
            }
        });
    });

    // Fermer l'info-bulle si l'utilisateur clique n'importe où ailleurs sur l'écran
    document.addEventListener('click', () => {
        hotspots.forEach(h => h.classList.remove('active'));
    });
});