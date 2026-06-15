document.addEventListener("DOMContentLoaded", () => {
    const checkboxes = document.querySelectorAll('.todo-list input[type="checkbox"]');
    const progressBar = document.getElementById("globalProgressBar");
    const statsText = document.getElementById("globalStats");

    // Identifiant unique pour éviter les conflits de stockage
    const STORAGE_KEY_PREFIX = "codealpha-cyberpink-task-";

    function updateProgress() {
        const total = checkboxes.length;
        let checkedCount = 0;

        checkboxes.forEach((checkbox, index) => {
            const listItem = checkbox.closest("li");
            if (checkbox.checked) {
                listItem.classList.add("completed");
                checkedCount++;
                // Sauvegarde l'état "coché"
                localStorage.setItem(`${STORAGE_KEY_PREFIX}${index}`, "checked");
            } else {
                listItem.classList.remove("completed");
                // Supprime l'état si décoché
                localStorage.removeItem(`${STORAGE_KEY_PREFIX}${index}`);
            }
        });

        // Calcul dynamique du pourcentage global
        const percentage = total > 0 ? Math.round((checkedCount / total) * 100) : 0;
        
        // Rafraîchissement des éléments de l'en-tête
        progressBar.style.width = `${percentage}%`;
        progressBar.textContent = `${percentage}%`;
        statsText.textContent = `${checkedCount} / ${total} ÉTAPES VALIDÉES`;
    }

    // Restauration de l'état des cases au chargement de la page
    checkboxes.forEach((checkbox, index) => {
        if (localStorage.getItem(`${STORAGE_KEY_PREFIX}${index}`) === "checked") {
            checkbox.checked = true;
        }
        // Écoute des clics sur chaque élément
        checkbox.addEventListener("change", updateProgress);
    });

    // Initialisation forcée au premier affichage
    updateProgress();
});