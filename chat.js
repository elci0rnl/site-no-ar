export class Chat {
  constructor({ baseURL }) {
    this.baseURL = baseURL;
  }
  async sendMessage(message) {
    const response = await fetch(`${this.baseURL}/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });
    const data = await response.json();
    return data.reply;
  }
}