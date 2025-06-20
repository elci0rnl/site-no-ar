// Selecionar os elementos do DOM
const widget = document.getElementById('chat-widget');
const toggle = document.getElementById('toggle-chat');
const log = document.getElementById('chat-log');
const input = document.getElementById('input');
const send = document.getElementById('send');

// Variável para armazenar o contexto da conversa (opcional)
let context = '';

// Alternar a visibilidade do widget do chatbot
toggle.addEventListener('click', () => {
  widget.style.display = widget.style.display === 'none' ? 'flex' : 'none';
});

// Função para enviar a mensagem e obter a resposta do chatbot
async function sendMessage() {
  const userMessage = input.value.trim(); // Obter o texto do input
  if (!userMessage) return; // Não enviar mensagens vazias

  appendMessage(userMessage, 'user'); // Adicionar a mensagem do usuário ao log
  input.value = ''; // Limpar o campo de input

  appendMessage('Digitando...', 'bot', true); // Exibir "Digitando..." enquanto espera a resposta

  try {
    // Fazer uma requisição para o backend no endpoint /api/chat
    const response = await fetch('/api/chat', {
      method: 'POST', // Método HTTP
      headers: { 'Content-Type': 'application/json' }, // Cabeçalhos HTTP
      body: JSON.stringify({ message: userMessage, context }), // Corpo da requisição
    });

    // Verificar se a resposta foi bem-sucedida
    if (!response.ok) {
      throw new Error('Erro na comunicação com o servidor');
    }

    // Processar a resposta do backend
    const data = await response.json();
    log.removeChild(log.lastChild); // Remover "Digitando..."
    appendMessage(data.reply, 'bot'); // Adicionar a resposta do chatbot ao log

    // Atualizar o contexto da conversa (opcional)
    context += `Usuário: ${userMessage}\nBot: ${data.reply}\n`;
    if (context.length > 2000) context = context.slice(-2000); // Limitar o tamanho do contexto
  } catch (error) {
    console.error('Erro:', error);
    log.removeChild(log.lastChild);
    appendMessage('Desculpe, ocorreu um erro. Tente novamente mais tarde.', 'bot');
  }
}

// Função para adicionar mensagens ao log
function appendMessage(text, sender, isTyping = false) {
  const messageElement = document.createElement('div');
  messageElement.className = `msg ${sender}`;
  messageElement.textContent = text;
  if (isTyping) messageElement.style.opacity = '0.6'; // Estilo para "Digitando..."
  log.appendChild(messageElement);
  log.scrollTop = log.scrollHeight; // Rolar o log para a mensagem mais recente
}

// Eventos para enviar a mensagem
send.addEventListener('click', sendMessage); // Clique no botão "Enviar"
input.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') sendMessage(); // Pressionar "Enter"
});