/* 
   ══════════════════════════════════════
   CHARTBOT FLOATING WIDGET
   ══════════════════════════════════════ 
*/

(function() {
    // ── Inject Styles ──
    const style = document.createElement('style');
    style.innerHTML = `
        .cb-widget {
            position: fixed; bottom: 30px; right: 30px; z-index: 10000;
            display: flex; flex-direction: column; align-items: flex-end;
            font-family: 'Inter', sans-serif;
        }
        .cb-bubble {
            width: 60px; height: 60px; border-radius: 50%;
            background: linear-gradient(135deg, #6366f1, #a855f7);
            box-shadow: 0 10px 25px rgba(99, 102, 241, 0.4);
            display: flex; align-items: center; justify-content: center;
            cursor: pointer; transition: transform 0.3s;
            font-size: 24px; position: relative;
        }
        .cb-bubble:hover { transform: scale(1.1) rotate(5deg); }
        .cb-bubble .cb-badge {
            position: absolute; top: -5px; right: -5px;
            background: #ef4444; color: white; font-size: 10px;
            padding: 3px 6px; border-radius: 10px; font-weight: bold;
        }
        
        .cb-window {
            width: 350px; height: 450px; background: #1e293b;
            border: 1px solid rgba(255,255,255,0.1); border-radius: 20px;
            margin-bottom: 15px; display: none; flex-direction: column;
            overflow: hidden; box-shadow: 0 20px 50px rgba(0,0,0,0.5);
            backdrop-filter: blur(10px);
        }
        .cb-window.active { display: flex; }
        
        .cb-header {
            padding: 15px 20px; background: rgba(255,255,255,0.03);
            border-bottom: 1px solid rgba(255,255,255,0.05);
            display: flex; justify-content: space-between; align-items: center;
        }
        .cb-header h4 { margin: 0; font-size: 14px; color: #fff; }
        .cb-close { cursor: pointer; opacity: 0.7; font-size: 18px; }
        .cb-close:hover { opacity: 1; }
        
        .cb-messages {
            flex: 1; padding: 15px; overflow-y: auto;
            display: flex; flex-direction: column; gap: 10px;
        }
        .cb-msg {
            max-width: 80%; padding: 10px 14px; border-radius: 14px;
            font-size: 13px; line-height: 1.4;
        }
        .cb-msg.bot { background: rgba(255,255,255,0.06); color: #e2e8f0; align-self: flex-start; }
        .cb-msg.user { background: #6366f1; color: white; align-self: flex-end; }
        
        .cb-footer {
            padding: 10px 15px; background: rgba(0,0,0,0.2);
            display: flex; gap: 8px;
        }
        .cb-footer input {
            flex: 1; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1);
            border-radius: 20px; padding: 8px 15px; color: white; font-size: 13px; outline: none;
        }
        .cb-footer button {
            background: #6366f1; border: none; border-radius: 50%;
            width: 34px; height: 34px; color: white; cursor: pointer;
            display: flex; align-items: center; justify-content: center;
        }
    `;
    document.head.appendChild(style);

    // ── Create Elements ──
    const widget = document.createElement('div');
    widget.className = 'cb-widget';
    widget.innerHTML = `
        <div class="cb-window" id="cb-window">
            <div class="cb-header">
                <h4>🤖 Assistant API Bank</h4>
                <div class="cb-close" id="cb-close">×</div>
            </div>
            <div class="cb-messages" id="cb-messages">
                <div class="cb-msg bot">Bonjour ! Je suis votre assistant de bord. Comment puis-je vous aider ?</div>
            </div>
            <div class="cb-footer">
                <input type="text" id="cb-input" placeholder="Posez une question...">
                <button id="cb-send">➤</button>
            </div>
            <div style="padding: 10px; font-size: 10px; text-align: center; color: rgba(255,255,255,0.3); background: rgba(0,0,0,0.1);">
                Pour un conseiller, visitez la <a href="/support" style="color: #6366f1; text-decoration: underline;">Messagerie</a>
            </div>
        </div>
        <div class="cb-bubble" id="cb-bubble">
            <span>💬</span>
            <div class="cb-badge">1</div>
        </div>
    `;
    document.body.appendChild(widget);

    // ── Logic ──
    const bubble = document.getElementById('cb-bubble');
    const win = document.getElementById('cb-window');
    const close = document.getElementById('cb-close');
    const input = document.getElementById('cb-input');
    const send = document.getElementById('cb-send');
    const msgBox = document.getElementById('cb-messages');

    // Restore State
    const savedMsg = JSON.parse(localStorage.getItem('cb_history') || '[]');
    const isWinOpen = localStorage.getItem('cb_open') === 'true';
    
    if (isWinOpen) win.classList.add('active');
    
    const renderMessage = (text, type) => {
        const d = document.createElement('div');
        d.className = `cb-msg ${type}`;
        d.innerText = text;
        msgBox.appendChild(d);
        msgBox.scrollTop = msgBox.scrollHeight;
    };

    savedMsg.forEach(m => renderMessage(m.text, m.type));

    bubble.onclick = () => {
        win.classList.toggle('active');
        const isOpen = win.classList.contains('active');
        localStorage.setItem('cb_open', isOpen);
        bubble.querySelector('.cb-badge').style.display = 'none';
    };
    
    close.onclick = () => {
        win.classList.remove('active');
        localStorage.setItem('cb_open', 'false');
    };

    const addMessage = (text, type) => {
        renderMessage(text, type);
        // Save to History
        const history = JSON.parse(localStorage.getItem('cb_history') || '[]');
        history.push({ text, type });
        localStorage.setItem('cb_history', JSON.stringify(history));
    };

    const handleSend = async () => {
        const text = input.value.trim();
        if(!text) return;
        
        input.value = '';
        addMessage(text, 'user');

        try {
            const res = await fetch('/support/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message: text })
            });
            const data = await res.json();
            addMessage(data.reply || "Désolé, j'ai rencontré un problème.", 'bot');
        } catch(e) {
            addMessage("Une erreur réseau est survenue.", 'bot');
        }
    };

    send.onclick = handleSend;
    input.onkeypress = (e) => { if(e.key === 'Enter') handleSend(); };
})();
