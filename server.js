const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

// Configuración de base de datos Supabase
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// 1) Health Check
app.get("/api/ping", (req, res) => {
  res.json({ estado: "OK", mensaje: "Servidor HRMS activo", timestamp: new Date() });
});

// 2) Descargar trabajadores (Garita)
app.get("/api/garita/trabajadores", async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT dni, nombre, empresa, habilitado,
             TO_CHAR(examen_medico_vence, 'YYYY-MM-DD') AS examen_medico_vence,
             TO_CHAR(induccion_vence, 'YYYY-MM-DD') AS induccion_vence
      FROM trabajadores`);
    res.json(r.rows);
  } catch (e) {
    console.error("Error en GET /api/garita/trabajadores:", e);
    res.status(500).json({ error: "Error al listar trabajadores" });
  }
});

// 3) Registrar marcaciones (Garita)
app.post("/api/garita/marcaciones", async (req, res) => {
  const m = req.body || {};
  const valida = m.id && /^\d{8}$/.test(m.dni || "") && ["entrada", "salida"].includes(m.tipo) &&
                 ["permitido", "denegado"].includes(m.resultado) && m.fecha_hora;

  if (!valida) {
    return res.status(400).json({ error: "Marcación inválida o incompleta" });
  }

  try {
    await pool.query(
      `INSERT INTO marcaciones (id, dni, tipo, resultado, motivo, fecha_hora, metodo, garita_id, ms_respuesta, demo)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (id) DO NOTHING`,
      [
        m.id, 
        m.dni, 
        m.tipo, 
        m.resultado, 
        m.motivo || "", 
        m.fecha_hora, 
        m.metodo || null, 
        m.garita_id || null,
        Number.isFinite(m.ms_respuesta) ? m.ms_respuesta : null, 
        m.demo === true
      ]
    );
    res.status(201).json({ ok: true });
  } catch (e) {
    console.error("Error en POST /api/garita/marcaciones:", e);
    res.status(500).json({ error: "Error al guardar la marcación" });
  }
});

// Otras rutas del proyecto
app.post("/api/contratistas/subir-documento", (req, res) => {
  res.json({ mensaje: "Documento recibido correctamente" });
});

app.post("/api/trabajadores/solicitar-permiso", (req, res) => {
  res.json({ mensaje: "Solicitud de permiso registrada correctamente" });
});

// Inicializar Servidor
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor backend corriendo en puerto ${PORT}`);
});