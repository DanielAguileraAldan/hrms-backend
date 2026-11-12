require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");

const app = express();
app.use(cors());
// Aumentamos el límite a 10MB para soportar archivos PDF/JPG de hasta 5MB
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

app.get("/", (req, res) => {
  res.json({
    sistema: "HRMS Minera Cordillera API",
    estado: "Operativo en la nube",
  });
});

// 1. LOGIN APP MÓVIL Y PORTALES
app.post("/api/trabajadores/login", async (req, res) => {
  try {
    const { dni, password } = req.body;
    if (!dni || !password) {
      return res.status(400).json({ error: "Debe ingresar DNI y contraseña" });
    }

    const dniLimpio = String(dni).replace(/[^0-9kK]/g, "").trim();
    const result = await pool.query(
      "SELECT * FROM trabajadores WHERE dni = $1",
      [dniLimpio]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Trabajador no encontrado" });
    }

    const trabajador = result.rows[0];
    const passValida = trabajador.password || trabajador.dni;

    if (String(password).trim() !== String(passValida).trim()) {
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    delete trabajador.password;

    res.json({
      success: true,
      token: `hrms-token-${trabajador.dni}-${Date.now()}`,
      mensaje: "Login exitoso",
      trabajador,
    });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ error: "Error interno del servidor" });
  }
});

// 2. GARITA: OBTENER NÓMINA DE TRABAJADORES
app.get("/api/garita/trabajadores", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT dni, nombre, empresa, habilitado, examen_medico_vence, induccion_vence FROM trabajadores ORDER BY nombre ASC"
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener trabajadores:", error);
    res.status(500).json({ error: "Error al consultar nómina" });
  }
});

// 3. GARITA: REGISTRAR MARCACIÓN
app.post("/api/garita/marcaciones", async (req, res) => {
  try {
    const { dni, tipo, permitido, motivo } = req.body;
    const result = await pool.query(
      `INSERT INTO marcaciones (dni, tipo, permitido, motivo, fecha)
       VALUES ($1, $2, $3, $4, NOW()) RETURNING *`,
      [dni, tipo || "ENTRADA", permitido !== false, motivo || "Validado en garita"]
    );
    res.status(201).json({
      success: true,
      mensaje: "Marcación registrada correctamente",
      marcacion: result.rows[0],
    });
  } catch (error) {
    console.error("Error al registrar marcación:", error);
    res.status(500).json({ error: "No se pudo registrar la marcación" });
  }
});

// Registro en memoria de documentos cargados para el MVP
let documentosCargados = [];

// 4. WEB CONTRATISTAS: HABILITAR + CARGA DE DOCUMENTO (HASTA 5MB)
app.post("/api/contratistas/documentos", async (req, res) => {
  try {
    const {
      dni,
      habilitado,
      examen_medico_vence,
      induccion_vence,
      archivo_nombre,
      archivo_tamano_mb,
      archivo_base64,
    } = req.body;

    const result = await pool.query(
      `UPDATE trabajadores
       SET habilitado = COALESCE($1, habilitado),
           examen_medico_vence = COALESCE($2, examen_medico_vence),
           induccion_vence = COALESCE($3, induccion_vence)
       WHERE dni = $4
       RETURNING dni, nombre, empresa, habilitado, examen_medico_vence, induccion_vence`,
      [habilitado, examen_medico_vence, induccion_vence, dni]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Trabajador no encontrado" });
    }

    if (archivo_nombre) {
      documentosCargados.unshift({
        id: Date.now(),
        dni,
        nombre_trabajador: result.rows[0].nombre,
        archivo_nombre,
        archivo_tamano_mb,
        archivo_base64,
        fecha: new Date().toLocaleString(),
      });
    }

    res.json({
      success: true,
      mensaje: "Documentación HSEC y archivo respaldados correctamente",
      trabajador: result.rows[0],
    });
  } catch (error) {
    console.error("Error actualizando documentos:", error);
    res.status(500).json({ error: "Error al actualizar documentación" });
  }
});

// Listar documentos HSEC subidos
app.get("/api/contratistas/archivos", (req, res) => {
  res.json(documentosCargados);
});

// 5. MÓDULO DE PERMISOS (SOLICITUD Y APROBACIÓN)
let solicitudesPermisos = [
  {
    id: 1,
    dni: "87654321",
    nombre: "María Torres Huamán",
    tipo: "Vacaciones",
    fecha_inicio: "2026-11-20",
    fecha_fin: "2026-11-25",
    motivo: "Descanso anual programado",
    estado: "PENDIENTE",
  },
];

app.post("/api/trabajadores/permisos", (req, res) => {
  const { dni, nombre, tipo, fecha_inicio, fecha_fin, motivo } = req.body;
  const nueva = {
    id: Date.now(),
    dni: dni || "87654321",
    nombre: nombre || "Trabajador Faena",
    tipo: tipo || "Permiso Administrativo",
    fecha_inicio: fecha_inicio || "2026-11-15",
    fecha_fin: fecha_fin || "2026-11-16",
    motivo: motivo || "Solicitud desde App Móvil",
    estado: "PENDIENTE",
  };
  solicitudesPermisos.unshift(nueva);
  res.status(201).json({ success: true, permiso: nueva });
});

app.get("/api/permisos", (req, res) => {
  res.json(solicitudesPermisos);
});

app.patch("/api/permisos/:id", (req, res) => {
  const permiso = solicitudesPermisos.find((p) => p.id == req.params.id);
  if (!permiso) {
    return res.status(404).json({ error: "Solicitud no encontrada" });
  }
  permiso.estado = req.body.estado;
  res.json({ success: true, permiso });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor HRMS Minera Cordillera corriendo en puerto ${PORT}`);
});