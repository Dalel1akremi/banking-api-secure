/**
 * FaceID Real AI Helper using face-api.js
 */
class FaceID {
    constructor() {
        this.modelsLoaded = false;
        this.faceapiLoaded = false;
        this.injectModal();
        this.loadScripts();
    }

    loadScripts() {
        if (window.faceapi) {
            this.faceapiLoaded = true;
            this.loadModels();
            return;
        }
        const script = document.createElement('script');
        script.src = "https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js";
        script.onload = () => {
            this.faceapiLoaded = true;
            this.loadModels();
        };
        document.head.appendChild(script);
    }

    async loadModels() {
        // Use a CDN for models
        const MODEL_URL = 'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights';
        try {
            await Promise.all([
                faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_URL),
                faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_URL),
                faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_URL)
            ]);
            this.modelsLoaded = true;
            console.log("FaceID AI Models Loaded");
        } catch (err) {
            console.error("Failed to load FaceAPI models", err);
        }
    }

    injectModal() {
        if (document.getElementById('faceid-modal')) return;

        const modalHtml = `
            <div id="faceid-modal" class="faceid-modal">
                <div class="faceid-container" id="faceid-container">
                    <!-- Verification Mode -->
                    <div id="faceid-verify-ui">
                        <div class="face-icon-wrapper">
                            <svg class="face-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M8 3H7a2 2 0 0 0-2 2v1a2 2 0 0 0 2 2h1"></path>
                                <path d="M16 3h1a2 2 0 0 1 2 2v1a2 2 0 0 1-2 2h-1"></path>
                                <path d="M16 21h1a2 2 0 0 0 2-2v-1a2 2 0 0 0-2-2h-1"></path>
                                <path d="M8 21H7a2 2 0 0 1-2-2v-1a2 2 0 0 1 2-2h1"></path>
                                <path d="M10 11h.01"></path>
                                <path d="M14 11h.01"></path>
                                <path d="M10 15a3.5 3.5 0 0 0 4 0"></path>
                            </svg>
                            <div class="face-scanner-line"></div>
                        </div>
                    </div>

                    <!-- Enrollment/Scan Mode -->
                    <div id="faceid-enroll-ui" style="display:none;">
                        <div class="enroll-container">
                            <video id="enroll-video" autoplay playsinline muted style="transform: scaleX(-1); width: 100%; height: 100%; object-fit: cover;"></video>
                            <div class="enroll-mask"></div>
                            <div class="enroll-ring">
                                <svg><circle cx="50%" cy="50%" r="120"></circle></svg>
                            </div>
                        </div>
                        <div class="enroll-hint" id="enroll-hint">Initialisation de l'IA...</div>
                    </div>

                    <!-- Common Success -->
                    <div class="success-check" style="position:relative; margin-bottom: 20px; display:none;" id="faceid-success-icon">
                        <svg width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                    </div>

                    <div class="faceid-text" id="faceid-title">Face ID</div>
                    <div class="faceid-subtext" id="faceid-subtitle">Authentification...</div>
                </div>
            </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
        
        if (!document.querySelector('link[href*="faceid.css"]')) {
            const link = document.createElement('link');
            link.rel = 'stylesheet'; link.href = '/static/faceid.css';
            document.head.appendChild(link);
        }
    }

    async scan() {
        const modal = document.getElementById('faceid-modal');
        const container = document.getElementById('faceid-container');
        const enrollUI = document.getElementById('faceid-enroll-ui');
        const verifyUI = document.getElementById('faceid-verify-ui');
        const video = document.getElementById('enroll-video');
        const subtitle = document.getElementById('faceid-subtitle');
        const hint = document.getElementById('enroll-hint');
        const successIcon = document.getElementById('faceid-success-icon');

        modal.classList.add('active');
        container.classList.remove('success', 'error');
        successIcon.style.display = 'none';

        // --- PHASE 1 : ANALYSE (2s) ---
        verifyUI.style.display = 'block';
        enrollUI.style.display = 'none';
        subtitle.innerText = "Analyse de Sécurité";
        hint.innerText = "Initialisation des protocoles...";
        await new Promise(r => setTimeout(r, 2000));

        // --- PHASE 2 : CAPTURE (2s) ---
        verifyUI.style.display = 'none';
        enrollUI.style.display = 'block';
        subtitle.innerText = "Capture Biométrique";
        hint.innerText = "Analyse des traits du visage...";

        try {
            const stream = await navigator.mediaDevices.getUserMedia({ 
                video: { width: { ideal: 640 }, height: { ideal: 480 } } 
            });
            video.srcObject = stream;
            this.currentStream = stream;

            await new Promise((resolve) => {
                video.onloadedmetadata = () => {
                    video.play();
                    resolve();
                };
            });

            if (!this.modelsLoaded) {
                while(!this.modelsLoaded) await new Promise(r => setTimeout(r, 200));
            }

            // On attend les 2s de "Capture" demandées
            await new Promise(r => setTimeout(r, 2000));
            
            // Capture descriptor réelle
            const descriptor = await this.captureFaceDescriptor(video);
            return descriptor; 
        } catch (err) {
            console.error("Scan error:", err);
            this.showResult(false, "Caméra non disponible");
            return null;
        }
    }

    async captureFaceDescriptor(video) {
        const hint = document.getElementById('enroll-hint');
        let attempts = 0;
        
        // Configuration Turbo pour la vitesse
        const options = new faceapi.TinyFaceDetectorOptions({ inputSize: 160, scoreThreshold: 0.5 });

        while(attempts < 50) {
            attempts++;
            if (!this.modelsLoaded) {
                await new Promise(r => setTimeout(r, 200));
                continue;
            }
            
            const detection = await faceapi.detectSingleFace(video, options)
                                        .withFaceLandmarks()
                                        .withFaceDescriptor();
            if (detection) {
                return Array.from(detection.descriptor);
            }
            
            // On scanne très vite sans trop de pause
            await new Promise(r => setTimeout(r, 100));
        }
        return null;
    }

    showResult(success, message) {
        const container = document.getElementById('faceid-container');
        const enrollUI = document.getElementById('faceid-enroll-ui');
        const successIcon = document.getElementById('faceid-success-icon');
        const subtitle = document.getElementById('faceid-subtitle');
        const modal = document.getElementById('faceid-modal');
        const hint = document.getElementById('enroll-hint');

        if (this.currentStream) {
            this.currentStream.getTracks().forEach(track => track.stop());
        }

        container.classList.remove('success', 'error');

        if (success) {
            container.classList.add('success');
            enrollUI.style.display = 'none';
            successIcon.style.display = 'block';
            subtitle.innerText = message || "Accès Autorisé";
            setTimeout(() => modal.classList.remove('active'), 1500);
        } else {
            container.classList.add('error');
            enrollUI.style.display = 'block'; // On garde la vidéo (figée) ou le masque
            subtitle.innerText = message || "Accès Refusé";
            hint.innerText = "Échec de la vérification";
            setTimeout(() => modal.classList.remove('active'), 3000);
        }
    }

    async enroll() {
        const descriptor = await this.scan();
        // On ne ferme pas le modal et on ne dit pas "Réussi" ici.
        // On retourne juste la signature pour que le serveur valide d'abord.
        if (descriptor) {
            return JSON.stringify(descriptor);
        }
        return null;
    }
}

window.faceid = new FaceID();
