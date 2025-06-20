require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const connectTodatabase = require("./database");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require('multer');
const path = require('path');
const WebSocket = require('ws');
const http = require('http');
const { OpenAI } = require("openai");
const uuid = require('uuid');
const axios = require('axios');

connectTodatabase();

const app = express();
app.use(express.json());
app.use(cors()); // Certifique-se de ter isso se for acessar de outro domínio

const server = http.createServer(app); // Servidor HTTP para Express e WebSocket
const wss = new WebSocket.Server({ server }); // Servidor WebSocket anexado ao servidor HTTP

const clients = new Set(); // Conjunto para armazenar clientes conectados


// ✅ Instancia do cliente OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const PORT = process.env.PORT || 5001;

//const mongoUri = process.env.MONGODB_URI;
//mongoose.connect(mongoUri, { useNewUrlParser: true, useUnifiedTopology: true });

// Configuração de CORS global
app.use(cors({
    origin: '*', // Permitir todas as origens (ajuste em produção)
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middlewares
app.use(express.json()); // Substitui bodyParser.json()
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Servir arquivos estáticos da pasta uploads
app.use('/', express.static(path.join(__dirname)));

// Exemplo de rota para validação
app.get('/api/teste', (req, res) => {
    res.json({ message: 'Backend funcionando com arquivos estáticos no diretório raiz!' });
});

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    senha: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

// Agenda Schema
const agendaSchema = new mongoose.Schema({
    title: String,
    datetime: Date,
    description: String,
});
const Agenda = mongoose.model("Agenda", agendaSchema);

// Visualizacao Schema
const visualizacaoSchema = new mongoose.Schema({
    secao: String,
    visualizacoes: Number,
});
const Visualizacao = mongoose.model("Visualizacao", visualizacaoSchema);

// Propriedade Schema
const propriedadeSchema = new mongoose.Schema({
    name: { type: String, required: true },
    status: { type: String, enum: ['disponivel', 'reservado'], required: true },
    type: { type: String, enum: ['casa', 'apartamento'], required: true },
    modalidade: { type: String, enum: ['venda', 'aluguel'], required: true },
    valor: { type: Number },
    descricao: { type: String },
    endereco: { type: String },
    images: [String], // Caminhos para as imagens
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: false }, // Referência ao usuário, deixe required: false para testes locais
}, { timestamps: true });
const Propriedade = mongoose.model("Propriedade", propriedadeSchema);

// Lead Schema
const leadSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true },
    phone: { type: String },
    createdAt: { type: Date, default: Date.now },
});
const Lead = mongoose.model("Lead", leadSchema);

// Venda Schema
const vendaSchema = new mongoose.Schema({
    valorVenda: { type: Number, required: true },
    dataVenda: { type: Date, required: true, default: Date.now },
});
const Venda = mongoose.model("Venda", vendaSchema);

// Anuncio Schema
const anuncioSchema = new mongoose.Schema({
    titulo: { type: String, required: true },
    descricao: { type: String },
    status: { type: String, enum: ['ativo', 'inativo', 'expirado'], default: 'ativo' },
    // Outros campos relevantes
});
const Anuncio = mongoose.model("Anuncio", anuncioSchema);

// Multer Configuração
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    },
});
const upload = multer({ storage: storage });

// --- ROTA PARA LISTAR PROPRIEDADES PÚBLICAS (DEVE SER A PRIMEIRA!) ---
app.get('/api/properties/public', async (req, res) => {
    try {
        const propriedades = await Propriedade.find();
        res.json(propriedades);
    } catch (error) {
        res.status(500).json({ error: 'Erro ao buscar propriedades.' });
    }
});

// --- CRIAR NOVA PROPRIEDADE (com upload de imagens via Multer) ---
app.post('/api/properties', upload.array('images', 10), async (req, res) => {
    try {
        const { name, status, type, modalidade, valor, descricao, endereco } = req.body;
        const imagePaths = req.files ? req.files.map(file => `/uploads/${file.filename}`) : [];

        const propriedade = new Propriedade({
            name,
            status,
            type,
            modalidade,
            valor,
            descricao,
            endereco,
            images: imagePaths,
            // user: userId, // Associe ao usuário se usar autenticação
        });

        const savedProperty = await propriedade.save();
        res.status(201).json(savedProperty);
    } catch (error) {
        res.status(400).json({ error: 'Erro ao criar propriedade.' });
    }
});

// --- EXCLUIR PROPRIEDADE ---
app.delete('/api/properties/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ error: 'ID inválido.' });
    }
    try {
        const result = await Propriedade.findByIdAndDelete(id);
        if (!result) return res.status(404).json({ error: 'Propriedade não encontrada.' });
        res.json({ message: 'Propriedade excluída com sucesso!' });
    } catch (error) {
        res.status(500).json({ error: 'Erro ao excluir propriedade.' });
    }
});

// --- ROTA DETALHES DE UMA PROPRIEDADE POR ID ---
app.get('/api/properties/:id', async (req, res) => {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) {
        return res.status(400).json({ erro: 'ID inválido.' });
    }
    try {
        const prop = await Propriedade.findById(id);
        if (prop) res.json(prop);
        else res.status(404).json({ erro: 'Propriedade não encontrada.' });
    } catch (err) {
        res.status(500).json({ erro: 'Erro ao buscar propriedade.' });
    }
});

// --- ROTAS DE AUTENTICAÇÃO ---
app.post(
    "/cadastro",
    [
        body("username").notEmpty().withMessage("Username is required"),
        body("email").isEmail().withMessage("Invalid email address"),
        body("senha").isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        try {
            const { username, email, senha } = req.body;
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                return res.status(400).json({ error: "Email already in use." });
            }
            const hashedPassword = await bcrypt.hash(senha, 10);
            const novoUsuario = new User({ username, email, senha: hashedPassword });
            await novoUsuario.save();
            res.status(201).json({ message: "Cadastro bem-sucedido!" });
        } catch (error) {
            console.error("Erro no cadastro:", error);
            res.status(500).json({ error: "Erro interno do servidor ao tentar cadastrar." });
        }
    }
);

app.post("/login", async (req, res) => {
    try {
        const { email, senha: senhaDigitada } = req.body;
        const usuario = await User.findOne({ email });
        if (!usuario) {
            return res.status(401).json({ error: "Email ou senha incorretos." });
        }
        const passwordMatch = await bcrypt.compare(senhaDigitada, usuario.senha);
        if (!passwordMatch) {
            return res.status(401).json({ error: "Email ou senha incorretos." });
        }
        const token = jwt.sign(
            { userId: usuario._id },
            process.env.JWT_SECRET || "Pira_Maravilh@7", // Use variável de ambiente em produção!
            { expiresIn: "1h" }
        );
        res.json({ token });
    } catch (error) {
        console.error("Erro no login:", error);
        res.status(500).json({ error: "Erro interno do servidor ao tentar fazer login." });
    }
});

// --- ROTAS DA AGENDA ---
app.post('/api/agenda', async (req, res) => {
    try {
        const agenda = new Agenda(req.body);
        await agenda.save();
        res.status(201).json(agenda);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/agenda', async (req, res) => {
    try {
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const agendas = await Agenda.find().sort({ datetime: -1 }).skip(skip).limit(limit);
        const totalAgendas = await Agenda.countDocuments();
        const totalPages = Math.ceil(totalAgendas / limit);

        res.json({
            agendas: agendas,
            totalPages: totalPages,
            currentPage: page,
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/agenda/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "ID de agendamento inválido" });
        }
        const agenda = await Agenda.findByIdAndUpdate(req.params.id, req.body, { new: true, runValidators: true });
        if (!agenda) {
            return res.status(404).json({ error: "Agendamento não encontrado" });
        }
        res.json(agenda);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/agenda/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "ID de agendamento inválido" });
        }
        const agenda = await Agenda.findByIdAndDelete(req.params.id);
        if (!agenda) {
            return res.status(404).json({ error: "Agendamento não encontrado" });
        }
        res.json({ message: "Agendamento excluído com sucesso" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- ROTAS DE VISUALIZAÇÕES ---
app.post("/api/visualizacoes/:secao/incrementar", async (req, res) => {
    const secao = req.params.secao;
    try {
        let visualizacao = await Visualizacao.findOne({ secao });
        if (visualizacao) {
            visualizacao.visualizacoes++;
        } else {
            visualizacao = new Visualizacao({ secao: secao, visualizacoes: 1 });
        }
        await visualizacao.save();
        res.json({ secao: visualizacao.secao, visualizacoes: visualizacao.visualizacoes });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- ROTAS PARA LEADS ---
app.post('/api/leads', async (req, res) => {
    try {
        const { name, email, phone } = req.body;
        const newLead = new Lead({ name, email, phone });
        const savedLead = await newLead.save();
        res.status(201).json(savedLead);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/leads', async (req, res) => {
    try {
        const leads = await Lead.find().sort({ createdAt: -1 });
        res.json(leads);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/leads/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ error: "ID de lead inválido" });
        }
        const deletedLead = await Lead.findByIdAndDelete(req.params.id);
        if (!deletedLead) {
            return res.status(404).json({ error: "Lead não encontrado" });
        }
        res.json({ message: "Lead excluído com sucesso" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/// --- ROTAS DO DASHBOARD (HTTP Endpoints) ---
app.get('/api/dashboard/resumo', async (req, res) => {
    try {
        const totalPropriedades = await Propriedade.countDocuments();
        const inicioDoDia = new Date();
        inicioDoDia.setHours(0, 0, 0, 0);
        const novosLeadsHoje = await Lead.countDocuments({ createdAt: { $gte: inicioDoDia } });
        const anunciosAtivos = await Anuncio.countDocuments({ status: 'ativo' });

        res.json({ totalPropriedades, novosLeads: novosLeadsHoje, anunciosAtivos });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/dashboard/leads-recentes', async (req, res) => { // Renomeado para consistência
    try {
        const leadsRecentes = await Lead.find().sort({ createdAt: -1 }).limit(5);
        res.json(leadsRecentes.map(lead => ({
            nome: lead.name,
            email: lead.email,
            telefone: lead.phone,
            data: lead.createdAt
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/dashboard/propriedades-populares', async (req, res) => {
    try {
        // Lógica de "popular" pode ser mais complexa (ex: baseada em visualizações, etc.)
        // Aqui, apenas as 3 mais recentes ou primeiras encontradas
        const propriedadesPopulares = await Propriedade.find().limit(3);
        res.json(propriedadesPopulares.map(prop => ({
            nome: prop.name,
            images: prop.images,
            status: prop.status,
            type: prop.type,
            modalidade: prop.modalidade
        })));
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Função para obter vendas mensais do banco de dados
async function obterVendasMensais() {
    try {
        const vendas = await Venda.aggregate([
            {
                $group: {
                    _id: { $month: '$dataVenda' }, // Agrupa por mês
                    totalVendas: { $sum: '$valorVenda' }
                }
            },
            {
                $project: {
                    _id: 0,
                    mesNumero: '$_id', // Mantém o número do mês para ordenação
                    mes: {
                        $switch: {
                            branches: [
                                { case: { $eq: ['$_id', 1] }, then: 'Janeiro' },
                                { case: { $eq: ['$_id', 2] }, then: 'Fevereiro' },
                                { case: { $eq: ['$_id', 3] }, then: 'Março' },
                                { case: { $eq: ['$_id', 4] }, then: 'Abril' },
                                { case: { $eq: ['$_id', 5] }, then: 'Maio' },
                                { case: { $eq: ['$_id', 6] }, then: 'Junho' },
                                { case: { $eq: ['$_id', 7] }, then: 'Julho' },
                                { case: { $eq: ['$_id', 8] }, then: 'Agosto' },
                                { case: { $eq: ['$_id', 9] }, then: 'Setembro' },
                                { case: { $eq: ['$_id', 10] }, then: 'Outubro' },
                                { case: { $eq: ['$_id', 11] }, then: 'Novembro' },
                                { case: { $eq: ['$_id', 12] }, then: 'Dezembro' }
                            ],
                            default: 'Desconhecido'
                        }
                    },
                    totalVendas: 1
                }
            },
            {
                $sort: { mesNumero: 1 } // Ordena pelo número do mês
            }
        ]);
        // Remove mesNumero antes de retornar, se não for necessário no frontend
        return vendas.map(({ mesNumero, ...resto }) => resto);
    } catch (error) {
        console.error('Erro ao buscar dados de vendas mensais:', error);
        // Retornar um array vazio ou estrutura padrão em caso de erro
        return Array(12).fill(null).map((_, i) => ({
            mes: new Date(0, i).toLocaleString('pt-BR', { month: 'long' }), // Nomes dos meses em português
            totalVendas: 0
        }));
    }
}

app.get('/api/dashboard/vendas-mensais', async (req, res) => {
    try {
        const vendasMensais = await obterVendasMensais();
        res.json(vendasMensais);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- CONFIGURAÇÃO E LÓGICA DO WEBSOCKET ---

wss.on('connection', (ws) => {
  console.log('Novo cliente conectado via WebSocket.');
  clients.add(ws);

  ws.on('message', async (data) => {
    const message = data.toString();

    if (!message) return;

    try {
      const completion = await openai.chat.completions.create({
        model: "gpt-4-turbo",
        messages: [
          { role: "system", content: "Você é um consultor virtual da Pra já Imóveis. Responda com linguagem amigável, clara e objetiva." },
          { role: "user", content: message }
        ],
        temperature: 0.7
      });

      const reply = completion.choices[0].message.content;
      ws.send(JSON.stringify({ type: "reply", content: reply }));

    } catch (err) {
      console.error('Erro ao responder via IA:', err);
      ws.send(JSON.stringify({ type: "error", content: "Erro ao processar a resposta da IA." }));
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    console.log('Cliente desconectado do WebSocket.');
  });

  ws.on('error', error => {
    console.error('Erro no WebSocket:', error);
  });
});


function broadcast(type, payload) {
    const message = JSON.stringify({ type, payload });
    clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(message);
                }
            });
        }
    //});
//}

// Intervalo para broadcast de dados do dashboard
const BROADCAST_INTERVAL = 5000; // 5 segundos

setInterval(async () => {
    try {
        // 1. Resumo
        const totalPropriedades = await Propriedade.countDocuments();
        const inicioDoDia = new Date();
        inicioDoDia.setHours(0, 0, 0, 0);
        const novosLeadsHoje = await Lead.countDocuments({ createdAt: { $gte: inicioDoDia } });
        const anunciosAtivos = await Anuncio.countDocuments({ status: 'ativo' });
        const resumo = { totalPropriedades, novosLeads: novosLeadsHoje, anunciosAtivos };
        broadcast('resumo', resumo);

        // 2. Leads Recentes
        const leadsRecentes = await Lead.find().sort({ createdAt: -1 }).limit(5);
        broadcast('leads-recentes', leadsRecentes.map(lead => ({
            nome: lead.name,
            email: lead.email,
            telefone: lead.phone,
            data: lead.createdAt
        })));

        // 3. Propriedades Populares (lógica simplificada)
        const propriedadesPopulares = await Propriedade.find().sort({ _id: -1 }).limit(3); // Exemplo: mais recentes
        broadcast('propriedades-populares', propriedadesPopulares.map(prop => ({
            _id: prop._id, // Enviar ID pode ser útil
            nome: prop.name,
            images: prop.images,
            status: prop.status,
            type: prop.type,
            modalidade: prop.modalidade
        })));

        // 4. Vendas Mensais
        const vendasMensais = await obterVendasMensais();
        broadcast('vendas-mensais', vendasMensais);

        // 5. Notificação de Novos Leads
        // Busca leads criados desde a última verificação (aproximadamente)
        const intervaloDate = new Date(Date.now() - BROADCAST_INTERVAL - 1000); // Adiciona 1s de margem
        const novosLeadsDesdeUltimoCheck = await Lead.find({ createdAt: { $gte: intervaloDate } });
        if (novosLeadsDesdeUltimoCheck.length > 0) {
            novosLeadsDesdeUltimoCheck.forEach(lead => {
                broadcast('notificacao', { mensagem: `Novo lead registrado: ${lead.name} (${lead.email})` });
            });
        }

    } catch (error) {
        console.error('Erro ao buscar e transmitir dados para broadcast:', error);
        // Considerar enviar uma mensagem de erro para os clientes ou logar mais detalhadamente
    }
}, BROADCAST_INTERVAL);

// Inicie o servidor HTTP (Express + WebSocket juntos!)
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor HTTP e WebSocket rodando na porta ${PORT}`);
});

// Rota de chat
app.post('/api/chat', async (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Falta mensagem.' });
  }

  try {
    const completion = await openai.chat.completions.create({
      model: "gpt-4-turbo", // mais poderosa e rápida
      messages: [
        { role: "system", content: "Você é um assistente especializado em imóveis." },
        { role: "user", content: message }
      ],
      temperature: 0.7 // controle da criatividade
    });

    const botReply = completion.choices[0].message.content;
    res.json({ reply: botReply });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao obter resposta da IA.' });
  }
});