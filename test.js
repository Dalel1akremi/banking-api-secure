
        function openRescheduleModal(id, date, time) {
            const modal = document.getElementById('modal-reschedule');
            const form = document.getElementById('reschedule-form');
            const dateInput = document.getElementById('reschedule-date');
            const timeInput = document.getElementById('reschedule-time');
            
            form.action = '/admin/appointments/reschedule/' + id;
            dateInput.value = date;
            timeInput.value = time;
            
            modal.style.display = 'flex';
        }

        function closeRescheduleModal() {
            document.getElementById('modal-reschedule').style.display = 'none';
        }

        // Close on click outside
        window.onclick = function(event) {
            const modal = document.getElementById('modal-reschedule');
            if (event.target == modal) {
                closeRescheduleModal();
            }
        };
        // SIEM Real-time Alerts Logic
        function initAlertsStream() {
            const container = document.getElementById('live-alerts-container');
            const eventSource = new EventSource('/api/admin/alerts/stream?token={{ access_token }}');

            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                if (data.type === 'connected') {
                    container.innerHTML = `<p style="color: #10b981; font-size: 12px;">${data.message}</p>`;
                    return;
                }

                // Create alert element
                const alertDiv = document.createElement('div');
                const color = data.severity === 'CRITICAL' ? '#ef4444' : (data.severity === 'HIGH' ? '#f59e0b' : '#818cf8');
                
                alertDiv.style.padding = '10px';
                alertDiv.style.borderRadius = '8px';
                alertDiv.style.background = 'rgba(255,255,255,0.03)';
                alertDiv.style.borderLeft = `3px solid ${color}`;
                alertDiv.style.fontSize = '12px';
                alertDiv.style.animation = 'slideIn 0.3s ease-out';

                alertDiv.innerHTML = `
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span style="color: ${color}; font-weight: bold;">${data.type.toUpperCase()}</span>
                        <span style="color: var(--text-muted); font-size: 10px;">${data.timestamp.split(' ')[1]}</span>
                    </div>
                    <div style="color: var(--text-main);">${data.message}</div>
                    <div style="margin-top: 5px; font-size: 10px; color: var(--text-muted);">Source: ${data.source} • IP: ${data.ip}</div>
                `;

                // Add to top of container
                container.prepend(alertDiv);
                
                // Play subtle sound or show notification if critical
                if (data.severity === 'CRITICAL') {
                    console.log('🚨 ALERTE CRITIQUE:', data.message);
                }
            };

            eventSource.onerror = function(err) {
                console.error("SSE Connection failed:", err);
                container.innerHTML = `<p style="color: #ef4444; font-size: 12px;">Flux déconnecté. Reconnexion...</p>`;
            };
        }

        // Initialize icons and alerts
        document.addEventListener('DOMContentLoaded', () => {
            initAlertsStream();
            try {
                lucide.createIcons();
            } catch (e) {
                console.error("Lucide icons failed:", e);
            }
        });

        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from { transform: translateX(20px); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    