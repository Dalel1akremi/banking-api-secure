/**
 * alerts.js — Gestion des messages d'alertes, d'erreurs et de succès.
 * Les messages restent affichés jusqu'à ce que l'utilisateur clique sur le bouton "OK".
 */
(function () {
    function setupAlerts() {
        document.querySelectorAll('.alert').forEach(function (alertEl) {
            // Éviter de rajouter plusieurs fois le bouton
            if (alertEl.querySelector('.alert-btn-ok')) {
                return;
            }

            // Bouton OK interactif
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'alert-btn-ok';
            btn.textContent = 'OK';
            btn.title = 'Fermer ce message';

            btn.onclick = function (e) {
                e.preventDefault();
                e.stopPropagation();
                alertEl.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
                alertEl.style.opacity = '0';
                alertEl.style.transform = 'translateY(-6px)';
                setTimeout(function () {
                    if (alertEl.parentNode) {
                        alertEl.parentNode.removeChild(alertEl);
                    }
                }, 250);
            };

            alertEl.appendChild(btn);
        });
    }

    // Exécution dès le chargement initial
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupAlerts);
    } else {
        setupAlerts();
    }

    // MutationObserver pour détecter et équiper les alertes créées dynamiquement
    var observer = new MutationObserver(function (mutations) {
        var shouldUpdate = false;
        mutations.forEach(function (m) {
            if (m.addedNodes && m.addedNodes.length > 0) {
                shouldUpdate = true;
            }
        });
        if (shouldUpdate) {
            setupAlerts();
        }
    });

    observer.observe(document.documentElement, {
        childList: true,
        subtree: true
    });
})();
