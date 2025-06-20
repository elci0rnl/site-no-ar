const mongoose = require("mongoose");

function connectTodatabase() {
  if (!process.env.DATABASE_URL) {
    console.error("A variável de ambiente DATABASE_URL não está definida!");
    process.exit(1); // Encerra o processo caso a URL não esteja definida
  }

  mongoose
    .connect(process.env.DATABASE_URL) // Remova as opções obsoletas
    .then(() => {
      console.log("🔥 Conectado ao MongoDB");
    })
    .catch((error) => {
      console.error("Erro ao conectar ao MongoDB:", error.message);
      console.error("Detalhes:", error);
    });

  const db = mongoose.connection;
  db.on("error", console.error.bind(console, "Erro de conexão com o MongoDB:"));
  db.once("open", () => {
    console.log("🔥 Conexão com o MongoDB estabelecida com sucesso!");
  });
}

module.exports = connectTodatabase;


