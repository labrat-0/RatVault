// File: dashboard/components/Chat.js
// XSS-safe implementation

class ChatComponent {
    constructor(containerId = 'chat-panel') {
        this.container = document.getElementById(containerId);
        this.messages = [];
        this.init();
    }

    init() {
        this.render();
        this.attachEventListeners();
    }

    render() {
        this.container.textContent = '';

        const chatWindow = document.createElement('div');
        chatWindow.className = 'chat-window';

        const header = document.createElement('div');
        header.className = 'chat-header';

        const title = document.createElement('h3');
        title.textContent = 'Knowledge Vault Chat';

        const closeBtn = document.createElement('button');
        closeBtn.className = 'chat-close';
        closeBtn.setAttribute('aria-label', 'Close chat');
        closeBtn.textContent = '×';

        header.appendChild(title);
        header.appendChild(closeBtn);

        const messagesDiv = document.createElement('div');
        messagesDiv.className = 'chat-messages';
        messagesDiv.id = 'chat-messages';

        const inputArea = document.createElement('div');
        inputArea.className = 'chat-input-area';

        const input = document.createElement('input');
        input.type = 'text';
        input.id = 'chat-input';
        input.placeholder = 'Ask anything about the vault...';
        input.setAttribute('autocomplete', 'off');

        const sendBtn = document.createElement('button');
        sendBtn.id = 'chat-send';
        sendBtn.className = 'chat-send-btn';
        sendBtn.setAttribute('aria-label', 'Send message');
        sendBtn.textContent = 'Send';

        inputArea.appendChild(input);
        inputArea.appendChild(sendBtn);

        chatWindow.appendChild(header);
        chatWindow.appendChild(messagesDiv);
        chatWindow.appendChild(inputArea);

        this.container.appendChild(chatWindow);
    }

    attachEventListeners() {
        const sendBtn = document.getElementById('chat-send');
        const input = document.getElementById('chat-input');
        const closeBtn = this.container.querySelector('.chat-close');

        sendBtn.addEventListener('click', () => this.sendMessage());
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.sendMessage();
        });
        closeBtn.addEventListener('click', () => this.toggleChat());
    }

    async sendMessage() {
        const input = document.getElementById('chat-input');
        const message = input.value.trim();

        if (!message) return;

        this.addMessageToUI('user', message);
        input.value = '';

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ message, history: this.messages })
            });

            const data = await response.json();

            if (data.reply) {
                this.addMessageToUI('assistant', data.reply);
                this.messages.push({ role: 'user', content: message });
                this.messages.push({ role: 'assistant', content: data.reply });
            } else if (data.error) {
                this.addMessageToUI('error', 'Error: ' + data.error);
            }
        } catch (error) {
            this.addMessageToUI('error', 'Failed to get response. Check console.');
            console.error('Chat error:', error);
        }
    }

    addMessageToUI(role, content) {
        const messagesDiv = document.getElementById('chat-messages');
        const messageEl = document.createElement('div');
        messageEl.className = 'chat-message chat-message-' + role;

        const p = document.createElement('p');
        p.textContent = content;  // textContent is XSS-safe

        messageEl.appendChild(p);
        messagesDiv.appendChild(messageEl);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    toggleChat() {
        this.container.classList.toggle('collapsed');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new ChatComponent('chat-panel');
});
