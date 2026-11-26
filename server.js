
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const multer = require("multer");
const { createClient } = require("@supabase/supabase-js");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cron = require("node-cron");

const app = express();

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ limit: "10mb", extended: true }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SECRET_KEY
);

const BUCKET = "documentos-hsec";
const MAX_FILE_SIZE = 5 * 1024 * 1024;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_SIZE },
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype !== "application/pdf" ||
      !file.originalname.toLowerCase().endsWith(".pdf")
    ) {
      return cb(new Error("Solo se permiten archivos PDF"));
    }

    cb(null, true);
  },
});

// ==========================================
// 1. AUTENTICACIÓN Y AUTORIZACIÓN
// ==========================================

function autenticarToken(req, res, next) {
  const encabezado = req.headers.authorization;

  if (!encabezado || !encabezado.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Se requiere un token de autenticación",
    });
  }

  const token = encabezado.slice(7).trim();

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);

    if (!usuario.dni || !usuario.rol || !usuario.tipo_usuario) {
      return res.status(401).json({
        error: "El token no contiene información válida",
      });
    }

    if (
      usuario.tipo_usuario === "trabajador" &&
      usuario.rol !== "trabajador"
    ) {
      return res.status(403).json({
        error: "Rol de trabajador no válido",
      });
    }

    if (
      usuario.tipo_usuario === "supervisor" &&
      !["supervisor", "admin"].includes(usuario.rol)
    ) {
      return res.status(403).json({
        error: "Rol de supervisor no válido",
      });
    }

    if (!["trabajador", "supervisor"].includes(usuario.tipo_usuario)) {
      return res.status(401).json({
        error: "Tipo de usuario no válido",
      });
    }

    req.usuario = usuario;
    next();
  } catch (error) {
    return res.status(401).json({
      error: "Token inválido o expirado",
    });
  }
}

function autorizarRoles(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.usuario || !rolesPermitidos.includes(req.usuario.rol)) {
      return res.status(403).json({
        error: "No tienes permisos para realizar esta operación",
      });
    }

    next();
  };
}

// Comprueba que el supervisor o administrador siga activo.
async function obtenerSupervisorActivo(dni) {
  const result = await pool.query(
    `SELECT dni, nombre, empresa, rol
     FROM supervisores
     WHERE dni = $1
       AND activo = TRUE`,
    [dni]
  );

  return result.rows[0] || null;
}

// ==========================================
// 2. INICIO
// ==========================================

app.get("/", (req, res) => {
  res.json({
    sistema: "HRMS Minera Cordillera API",
    estado: "Operativo en la nube",
  });
});

// ==========================================
// 3. LOGIN DE TRABAJADORES Y SUPERVISORES
// ==========================================

app.post("/api/trabajadores/login", async (req, res) => {
  try {
    const { dni, password } = req.body;

    if (!dni || !password) {
      return res.status(400).json({
        error: "Debe ingresar DNI y contraseña",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET no está configurada");

      return res.status(500).json({
        error: "Configuración de seguridad incompleta",
      });
    }

    const dniLimpio = String(dni).replace(/[^0-9kK]/g, "").trim();

    const trabajadorResult = await pool.query(
      `SELECT dni, nombre, empresa, habilitado,
              examen_medico_vence, induccion_vence,
              dias_vacaciones_disponibles,
              examen_medico_pdf_url, induccion_pdf_url,
              password_hash
       FROM trabajadores
       WHERE dni = $1`,
      [dniLimpio]
    );

    let cuenta = null;
    let tipoUsuario = null;

    if (trabajadorResult.rows.length > 0) {
      cuenta = trabajadorResult.rows[0];
      tipoUsuario = "trabajador";
    } else {
      const supervisorResult = await pool.query(
        `SELECT dni, nombre, empresa,
                password_hash, rol, activo
         FROM supervisores
         WHERE dni = $1`,
        [dniLimpio]
      );

      if (supervisorResult.rows.length > 0) {
        cuenta = supervisorResult.rows[0];
        tipoUsuario = "supervisor";
      }
    }

    if (!cuenta || !cuenta.password_hash) {
      return res.status(401).json({
        error: "DNI o contraseña incorrectos",
      });
    }

    if (tipoUsuario === "supervisor" && !cuenta.activo) {
      return res.status(403).json({
        error: "La cuenta se encuentra desactivada",
      });
    }

    const passwordValida = await bcrypt.compare(
      String(password),
      cuenta.password_hash
    );

    if (!passwordValida) {
      return res.status(401).json({
        error: "DNI o contraseña incorrectos",
      });
    }

    const rol = tipoUsuario === "trabajador" ? "trabajador" : cuenta.rol;

    if (
      tipoUsuario === "supervisor" &&
      !["supervisor", "admin"].includes(rol)
    ) {
      return res.status(403).json({
        error: "La cuenta tiene un rol no válido",
      });
    }

    const token = jwt.sign(
      {
        dni: cuenta.dni,
        rol,
        tipo_usuario: tipoUsuario,
      },
      process.env.JWT_SECRET,
      { expiresIn: "8h" }
    );

    delete cuenta.password_hash;

    if (tipoUsuario === "trabajador") {
      return res.json({
        success: true,
        token,
        tipo: "Bearer",
        expira_en: "8 horas",
        mensaje: "Login exitoso",
        trabajador: {
          ...cuenta,
          rol,
        },
      });
    }

    return res.json({
      success: true,
      token,
      tipo: "Bearer",
      expira_en: "8 horas",
      mensaje: "Login exitoso",
      supervisor: {
        ...cuenta,
        rol,
      },
    });
  } catch (error) {
    console.error("Error en login:", error);

    res.status(500).json({
      error: "Error interno del servidor",
    });
  }
});

// ==========================================
// 4. GARITA: OBTENER NÓMINA DE TRABAJADORES
// ==========================================
// Esta ruta queda sin JWT porque garita.html consulta la nómina
// directamente y el contrato actual del agente no contempla token.
// IMPORTANTE: es una ruta pública; revisar esta decisión antes de producción.

app.get("/api/garita/trabajadores", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT dni, nombre, empresa, habilitado,
              to_char(examen_medico_vence, 'YYYY-MM-DD') AS examen_medico_vence,
              to_char(induccion_vence, 'YYYY-MM-DD') AS induccion_vence
       FROM trabajadores
       ORDER BY nombre ASC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error al obtener trabajadores para garita:", error);

    res.status(500).json({
      error: "Error al consultar nómina",
    });
  }
});

// ==========================================
// 5. GARITA: REGISTRAR MARCACIÓN
// ==========================================
// La ruta acepta el formato del agente offline-first.
// El ID de la marcación es la clave de idempotencia.
// Los reintentos no generan duplicados.

app.post("/api/garita/marcaciones", async (req, res) => {
  try {
    const {
      id,
      dni,
      tipo,
      resultado,
      motivo,
      fecha_hora,
      metodo,
      garita_id,
      ms_respuesta,
      verificacion,
      verificacion_ok,
      ms_verificacion,
      demo,
    } = req.body || {};

    const idLimpio = typeof id === "string" ? id.trim() : "";
    const dniLimpio = typeof dni === "string" ? dni.trim() : "";

    if (idLimpio.length < 8 || idLimpio.length > 80) {
      return res.status(400).json({
        error: "El ID debe tener entre 8 y 80 caracteres",
      });
    }

    if (!/^\d{8}$/.test(dniLimpio)) {
      return res.status(400).json({
        error: "El DNI debe contener exactamente 8 dígitos",
      });
    }

    if (!["entrada", "salida"].includes(tipo)) {
      return res.status(400).json({
        error: "Tipo no válido. Use entrada o salida",
      });
    }

    if (!["permitido", "denegado"].includes(resultado)) {
      return res.status(400).json({
        error: "Resultado no válido. Use permitido o denegado",
      });
    }

    const fechaValida =
      typeof fecha_hora === "string" &&
      /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i.test(
        fecha_hora
      ) &&
      Number.isFinite(Date.parse(fecha_hora));

    if (!fechaValida) {
      return res.status(400).json({
        error: "fecha_hora debe ser una fecha ISO 8601 con zona horaria",
      });
    }

    const textoOpcional = (valor, campo, maximo = 200) => {
      if (valor === undefined || valor === null) return null;

      if (typeof valor !== "string" || valor.length > maximo) {
        throw new Error(`${campo} debe ser texto de hasta ${maximo} caracteres`);
      }

      return valor.trim() || null;
    };

    const enteroOpcional = (valor, campo) => {
      if (valor === undefined || valor === null) return null;

      if (!Number.isInteger(valor) || valor < 0) {
        throw new Error(`${campo} debe ser un entero mayor o igual a cero`);
      }

      return valor;
    };

    const metodoLimpio = textoOpcional(metodo, "metodo", 80);
    const garitaLimpia = textoOpcional(garita_id, "garita_id", 100);
    const verificacionLimpia = textoOpcional(
      verificacion,
      "verificacion",
      100
    );
    const motivoLimpio =
      textoOpcional(motivo, "motivo", 500) || "";

    const msRespuestaLimpio = enteroOpcional(
      ms_respuesta,
      "ms_respuesta"
    );
    const msVerificacionLimpio = enteroOpcional(
      ms_verificacion,
      "ms_verificacion"
    );

    if (
      verificacion_ok !== undefined &&
      verificacion_ok !== null &&
      typeof verificacion_ok !== "boolean"
    ) {
      return res.status(400).json({
        error: "verificacion_ok debe ser verdadero o falso",
      });
    }

    if (demo !== undefined && typeof demo !== "boolean") {
      return res.status(400).json({
        error: "demo debe ser verdadero o falso",
      });
    }

    const result = await pool.query(
      `INSERT INTO marcaciones
       (id, dni, tipo, resultado, motivo, fecha_hora,
        metodo, garita_id, ms_respuesta, demo,
        verificacion, verificacion_ok, ms_verificacion)
       VALUES ($1, $2, $3, $4, $5, $6,
               $7, $8, $9, $10, $11, $12, $13)
       ON CONFLICT (id) DO NOTHING
       RETURNING id`,
      [
        idLimpio,
        dniLimpio,
        tipo,
        resultado,
        motivoLimpio,
        fecha_hora,
        metodoLimpio,
        garitaLimpia,
        msRespuestaLimpio,
        demo ?? false,
        verificacionLimpia,
        verificacion_ok ?? null,
        msVerificacionLimpio,
      ]
    );

    const duplicada = result.rows.length === 0;

    return res.status(duplicada ? 200 : 201).json({
      success: true,
      duplicada,
      id: idLimpio,
      mensaje: duplicada
        ? "La marcación ya estaba registrada"
        : "Marcación registrada correctamente",
    });
  } catch (error) {
    if (
      error.message &&
      (
        error.message.includes("debe ser texto") ||
        error.message.includes("debe ser un entero")
      )
    ) {
      return res.status(400).json({
        error: error.message,
      });
    }

    console.error("Error al registrar marcación:", error);

    res.status(500).json({
      error: "No se pudo registrar la marcación",
    });
  }
});

// ==========================================
// 6. DOCUMENTOS HSEC: SUBIR PDF
// ==========================================

app.post(
  "/api/contratistas/documentos",
  autenticarToken,
  autorizarRoles("supervisor", "admin"),
  upload.single("documento"),
  async (req, res) => {
    let rutaArchivo = null;

    try {
      const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

      if (!supervisor) {
        return res.status(403).json({
          error: "La cuenta de supervisor está desactivada o no existe",
        });
      }

      const { dni, tipo_documento, fecha_vencimiento } = req.body;

      if (!dni || !tipo_documento || !req.file) {
        return res.status(400).json({
          error: "Debe ingresar DNI, tipo de documento y archivo PDF",
        });
      }

      const tiposPermitidos = ["EXAMEN_MEDICO", "INDUCCION_HSEC"];

      if (!tiposPermitidos.includes(tipo_documento)) {
        return res.status(400).json({
          error: "Tipo de documento no válido",
        });
      }

      let fechaLimpia = null;

      if (fecha_vencimiento !== undefined && fecha_vencimiento !== "") {
        const fechaTexto = String(fecha_vencimiento).trim();
        const formatoValido = /^\d{4}-\d{2}-\d{2}$/.test(fechaTexto);
        const fechaObjeto = new Date(`${fechaTexto}T00:00:00Z`);

        if (
          !formatoValido ||
          Number.isNaN(fechaObjeto.getTime()) ||
          fechaObjeto.toISOString().slice(0, 10) !== fechaTexto
        ) {
          return res.status(400).json({
            error: "La fecha de vencimiento debe tener formato YYYY-MM-DD",
          });
        }

        fechaLimpia = fechaTexto;
      }

      if (req.file.buffer.subarray(0, 5).toString() !== "%PDF-") {
        return res.status(400).json({
          error: "El archivo no tiene una firma PDF válida",
        });
      }

      const trabajadorResult = await pool.query(
        `SELECT dni, nombre,
                examen_medico_vence,
                induccion_vence,
                examen_medico_pdf_url,
                induccion_pdf_url
         FROM trabajadores
         WHERE dni = $1`,
        [dni]
      );

      if (trabajadorResult.rows.length === 0) {
        return res.status(404).json({
          error: "Trabajador no encontrado",
        });
      }

      const nombreSeguro = crypto.randomUUID() + ".pdf";
      rutaArchivo = `${dni}/${tipo_documento}/${nombreSeguro}`;

      const { error: storageError } = await supabase.storage
        .from(BUCKET)
        .upload(rutaArchivo, req.file.buffer, {
          contentType: "application/pdf",
          upsert: false,
        });

      if (storageError) {
        console.error("Error en Supabase Storage:", storageError);

        return res.status(500).json({
          error: "No se pudo almacenar el PDF",
        });
      }

      const esExamen = tipo_documento === "EXAMEN_MEDICO";

      const columnaPdf = esExamen
        ? "examen_medico_pdf_url"
        : "induccion_pdf_url";

      const columnaFecha = esExamen
        ? "examen_medico_vence"
        : "induccion_vence";

      try {
        const actualizacion = await pool.query(
          `UPDATE trabajadores
           SET ${columnaPdf} = $1,
               ${columnaFecha} = COALESCE($2::date, ${columnaFecha}),
               habilitado = CASE
                 WHEN
                   (
                     CASE
                       WHEN $3 = 'EXAMEN_MEDICO'
                         THEN $1
                       ELSE examen_medico_pdf_url
                     END
                   ) IS NOT NULL
                   AND
                   (
                     CASE
                       WHEN $3 = 'INDUCCION_HSEC'
                         THEN $1
                       ELSE induccion_pdf_url
                     END
                   ) IS NOT NULL
                   AND
                   COALESCE(
                     CASE
                       WHEN $3 = 'EXAMEN_MEDICO'
                         THEN COALESCE($2::date, examen_medico_vence)
                       ELSE examen_medico_vence
                     END,
                     NULL
                   ) >= (NOW() AT TIME ZONE 'America/Santiago')::date
                   AND
                   COALESCE(
                     CASE
                       WHEN $3 = 'INDUCCION_HSEC'
                         THEN COALESCE($2::date, induccion_vence)
                       ELSE induccion_vence
                     END,
                     NULL
                   ) >= (NOW() AT TIME ZONE 'America/Santiago')::date
                 THEN TRUE
                 ELSE FALSE
               END
           WHERE dni = $4
           RETURNING dni, nombre, habilitado,
                     examen_medico_vence,
                     induccion_vence`,
          [rutaArchivo, fechaLimpia, tipo_documento, dni]
        );

        return res.status(201).json({
          success: true,
          mensaje: "Documento almacenado correctamente",
          trabajador: actualizacion.rows[0],
          tipo_documento,
          archivo: rutaArchivo,
        });
      } catch (dbError) {
        await supabase.storage.from(BUCKET).remove([rutaArchivo]);
        throw dbError;
      }
    } catch (error) {
      console.error("Error al cargar documento HSEC:", error);

      res.status(500).json({
        error: "Error al procesar el documento",
      });
    }
  }
);

// ==========================================
// 6.1 LISTAR DOCUMENTOS HSEC
// ==========================================

app.get(
  "/api/contratistas/archivos",
  autenticarToken,
  autorizarRoles("supervisor", "admin"),
  async (req, res) => {
    try {
      const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

      if (!supervisor) {
        return res.status(403).json({
          error: "La cuenta de supervisor está desactivada o no existe",
        });
      }

      const result = await pool.query(
        `SELECT dni, nombre, empresa,
                examen_medico_pdf_url,
                induccion_pdf_url
         FROM trabajadores
         WHERE examen_medico_pdf_url IS NOT NULL
            OR induccion_pdf_url IS NOT NULL
         ORDER BY nombre ASC`
      );

      const documentos = [];

      for (const trabajador of result.rows) {
        for (const tipo of [
          {
            nombre: "EXAMEN_MEDICO",
            ruta: trabajador.examen_medico_pdf_url,
          },
          {
            nombre: "INDUCCION_HSEC",
            ruta: trabajador.induccion_pdf_url,
          },
        ]) {
          if (!tipo.ruta) continue;

          const { data, error } = await supabase.storage
            .from(BUCKET)
            .createSignedUrl(tipo.ruta, 300);

          documentos.push({
            dni: trabajador.dni,
            nombre_trabajador: trabajador.nombre,
            empresa: trabajador.empresa,
            tipo_documento: tipo.nombre,
            archivo: tipo.ruta,
            url: error ? null : data.signedUrl,
          });
        }
      }

      res.json(documentos);
    } catch (error) {
      console.error("Error al listar documentos:", error);

      res.status(500).json({
        error: "No se pudieron consultar los documentos",
      });
    }
  }
);

// ==========================================
// 7. MÓDULO DE PERMISOS
// ==========================================
// ==========================================
// CONSULTAR SALDO DE VACACIONES DEL TRABAJADOR
// ==========================================

app.get(
  "/api/trabajadores/saldo-vacaciones",
  autenticarToken,
  autorizarRoles("trabajador"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT dias_vacaciones_disponibles
         FROM trabajadores
         WHERE dni = $1`,
        [req.usuario.dni]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Trabajador no encontrado",
        });
      }

      res.json({
        success: true,
        dias_vacaciones_disponibles:
          Number(result.rows[0].dias_vacaciones_disponibles),
      });
    } catch (error) {
      console.error("Error al consultar saldo de vacaciones:", error);

      res.status(500).json({
        error: "Error al consultar el saldo de vacaciones",
      });
    }
  }
);

app.post(
  "/api/trabajadores/permisos",
  autenticarToken,
  autorizarRoles("trabajador"),
  async (req, res) => {
    try {
      const {
        tipo,
        fecha_inicio,
        fecha_fin,
        motivo,
        con_goce_sueldo,
      } = req.body;

      if (!tipo || !fecha_inicio || !fecha_fin) {
        return res.status(400).json({
          error: "Debe ingresar tipo y fechas del permiso",
        });
      }

      const result = await pool.query(
        `INSERT INTO permisos
         (dni, tipo, fecha_hora_inicio, fecha_hora_fin,
          con_goce_sueldo, motivo, estado)
         VALUES ($1, $2, $3, $4, $5, $6, 'solicitado')
         RETURNING *`,
        [
          req.usuario.dni,
          tipo,
          fecha_inicio,
          fecha_fin,
          con_goce_sueldo ?? false,
          motivo || "Solicitud desde App Móvil",
        ]
      );

      const permiso = result.rows[0];

      res.status(201).json({
        success: true,
        permiso: {
          ...permiso,
          fecha_inicio: permiso.fecha_hora_inicio,
          fecha_fin: permiso.fecha_hora_fin,
        },
      });
    } catch (error) {
      console.error("Error al crear permiso:", error);

      res.status(500).json({
        error: "No se pudo registrar la solicitud de permiso",
      });
    }
  }
);

app.get(
  "/api/permisos",
  autenticarToken,
  autorizarRoles("trabajador", "supervisor", "admin"),
  async (req, res) => {
    try {
      let consulta;
      let parametros = [];

      if (req.usuario.rol === "trabajador") {
        consulta = `
          SELECT p.*, t.nombre,
                 p.fecha_hora_inicio AS fecha_inicio,
                 p.fecha_hora_fin AS fecha_fin
          FROM permisos p
          LEFT JOIN trabajadores t ON t.dni = p.dni
          WHERE p.dni = $1
          ORDER BY p.fecha_hora_inicio DESC
        `;

        parametros = [req.usuario.dni];
      } else {
        const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

        if (!supervisor) {
          return res.status(403).json({
            error: "La cuenta de supervisor está desactivada o no existe",
          });
        }

        consulta = `
          SELECT p.*, t.nombre,
                 p.fecha_hora_inicio AS fecha_inicio,
                 p.fecha_hora_fin AS fecha_fin
          FROM permisos p
          LEFT JOIN trabajadores t ON t.dni = p.dni
          ORDER BY p.fecha_hora_inicio DESC
        `;
      }

      const result = await pool.query(consulta, parametros);
      res.json(result.rows);
    } catch (error) {
      console.error("Error al obtener permisos:", error);

      res.status(500).json({
        error: "Error al consultar las solicitudes",
      });
    }
  }
);

app.patch(
  "/api/permisos/:id",
  autenticarToken,
  autorizarRoles("supervisor", "admin"),
  async (req, res) => {
    try {
      const { id } = req.params;
      const { estado, motivo_rechazo } = req.body;

      const uuidValido =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

      if (!uuidValido.test(id)) {
        return res.status(400).json({
          error: "El identificador del permiso no es válido",
        });
      }

      if (!["aprobado", "rechazado"].includes(estado)) {
        return res.status(400).json({
          error: "Estado no válido. Use aprobado o rechazado",
        });
      }

      const motivo = String(motivo_rechazo || "").trim();

      if (estado === "rechazado" && !motivo) {
        return res.status(400).json({
          error: "Debe ingresar un motivo de rechazo",
        });
      }

      const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

      if (!supervisor) {
        return res.status(403).json({
          error: "La cuenta de supervisor está desactivada o no existe",
        });
      }

      const result = await pool.query(
        `UPDATE permisos
         SET estado = $1,
             motivo_rechazo = $2,
             aprobado_por = $3,
             aprobado_en = NOW()
         WHERE id = $4
           AND estado = 'solicitado'
         RETURNING *`,
        [
          estado,
          estado === "rechazado" ? motivo : null,
          supervisor.nombre,
          id,
        ]
      );

      if (result.rows.length === 0) {
        const existente = await pool.query(
          "SELECT id, estado FROM permisos WHERE id = $1",
          [id]
        );

        if (existente.rows.length === 0) {
          return res.status(404).json({
            error: "Solicitud no encontrada",
          });
        }

        return res.status(409).json({
          error: "La solicitud ya fue procesada",
          estado_actual: existente.rows[0].estado,
        });
      }

      const permiso = result.rows[0];

      const trabajadorResult = await pool.query(
        "SELECT nombre FROM trabajadores WHERE dni = $1",
        [permiso.dni]
      );

      res.json({
        success: true,
        permiso: {
          ...permiso,
          nombre: trabajadorResult.rows[0]?.nombre || null,
          fecha_inicio: permiso.fecha_hora_inicio,
          fecha_fin: permiso.fecha_hora_fin,
        },
      });
    } catch (error) {
      console.error("Error al actualizar permiso:", error);

      res.status(500).json({
        error: "No se pudo actualizar la solicitud",
      });
    }
  }
);

// ==========================================
// 8. MÓDULO DE VACACIONES
// ==========================================

// ------------------------------------------
// 8.1 CREAR SOLICITUD DE VACACIONES
// ------------------------------------------

app.post(
  "/api/vacaciones",
  autenticarToken,
  autorizarRoles("trabajador"),
  async (req, res) => {
    try {
      const { fecha_inicio, fecha_fin, motivo, observacion } = req.body;

      if (!fecha_inicio || !fecha_fin) {
        return res.status(400).json({
          error: "Debe ingresar la fecha de inicio y la fecha de término",
        });
      }

      const fechaValida = (fecha) => {
        if (
          typeof fecha !== "string" ||
          !/^\d{4}-\d{2}-\d{2}$/.test(fecha)
        ) {
          return false;
        }

        const fechaObjeto = new Date(`${fecha}T00:00:00Z`);

        return (
          !Number.isNaN(fechaObjeto.getTime()) &&
          fechaObjeto.toISOString().slice(0, 10) === fecha
        );
      };

      if (!fechaValida(fecha_inicio) || !fechaValida(fecha_fin)) {
        return res.status(400).json({
          error: "Las fechas deben tener formato YYYY-MM-DD y ser válidas",
        });
      }

      if (fecha_fin < fecha_inicio) {
        return res.status(400).json({
          error: "La fecha de término no puede ser anterior a la fecha de inicio",
        });
      }

      const observacionLimpia = String(
        observacion ?? motivo ?? ""
      ).trim();

      const inicio = new Date(`${fecha_inicio}T00:00:00Z`);
      const termino = new Date(`${fecha_fin}T00:00:00Z`);

      // Se cuentan ambos días, incluyendo inicio y término.
      const diasCorridos =
        Math.round((termino - inicio) / 86400000) + 1;

      // El DNI se obtiene del token, no del cuerpo de la petición.
      const trabajadorResult = await pool.query(
        `SELECT dni, nombre, dias_vacaciones_disponibles
         FROM trabajadores
         WHERE dni = $1`,
        [req.usuario.dni]
      );

      if (trabajadorResult.rows.length === 0) {
        return res.status(404).json({
          error: "Trabajador no encontrado",
        });
      }

      const trabajador = trabajadorResult.rows[0];
      const saldo = Number(trabajador.dias_vacaciones_disponibles);

      if (!Number.isFinite(saldo) || saldo < diasCorridos) {
        return res.status(409).json({
          error: "No tienes suficientes días de vacaciones disponibles",
          dias_solicitados: diasCorridos,
          dias_disponibles: Number.isFinite(saldo) ? saldo : null,
        });
      }

      // dias_corridos es una columna generada por PostgreSQL.
      // No debe enviarse en el INSERT: la base de datos calcula su valor.
      const result = await pool.query(
        `INSERT INTO vacaciones
          (dni, fecha_inicio, fecha_fin, observacion)
         VALUES ($1, $2, $3, $4)
         RETURNING *`,
        [
          trabajador.dni,
          fecha_inicio,
          fecha_fin,
          observacionLimpia,
        ]
      );

      return res.status(201).json({
        success: true,
        mensaje: "Solicitud de vacaciones registrada correctamente",
        vacaciones: {
          ...result.rows[0],
          nombre: trabajador.nombre,
          dias_vacaciones_disponibles: saldo,
        },
      });
    } catch (error) {
      console.error("Error al crear solicitud de vacaciones:", error);

      return res.status(500).json({
        error: "No se pudo registrar la solicitud de vacaciones",
      });
    }
  }
);

// ------------------------------------------
// 8.2 OBTENER SOLICITUDES DE VACACIONES
// ------------------------------------------

app.get(
  "/api/vacaciones",
  autenticarToken,
  autorizarRoles("trabajador", "supervisor", "admin"),
  async (req, res) => {
    try {
      let consulta;
      let parametros = [];

      if (req.usuario.rol === "trabajador") {
        consulta = `
          SELECT v.*, t.nombre,
                 t.dias_vacaciones_disponibles
          FROM vacaciones v
          LEFT JOIN trabajadores t ON t.dni = v.dni
          WHERE v.dni = $1
          ORDER BY v.creado_en DESC
        `;

        parametros = [req.usuario.dni];
      } else {
        const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

        if (!supervisor) {
          return res.status(403).json({
            error: "La cuenta de supervisor está desactivada o no existe",
          });
        }

        consulta = `
          SELECT v.*, t.nombre,
                 t.dias_vacaciones_disponibles
          FROM vacaciones v
          LEFT JOIN trabajadores t ON t.dni = v.dni
          ORDER BY v.creado_en DESC
        `;
      }

      const result = await pool.query(consulta, parametros);
      res.json(result.rows);
    } catch (error) {
      console.error("Error al obtener vacaciones:", error);

      res.status(500).json({
        error: "Error al consultar las solicitudes de vacaciones",
      });
    }
  }
);

// ------------------------------------------
// 8.3 APROBAR O RECHAZAR SOLICITUDES
// ------------------------------------------

app.patch(
  "/api/vacaciones/:id",
  autenticarToken,
  autorizarRoles("supervisor", "admin"),
  async (req, res) => {
    let client = null;
    let transaccionIniciada = false;

    try {
      const { id } = req.params;
      const { estado, motivo_rechazo } = req.body;

      const uuidValido =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

      if (!uuidValido.test(id)) {
        return res.status(400).json({
          error: "El identificador de vacaciones no es válido",
        });
      }

      if (!["aprobada", "rechazada"].includes(estado)) {
        return res.status(400).json({
          error: "Estado no válido. Use aprobada o rechazada",
        });
      }

      const motivo = String(motivo_rechazo || "").trim();

      if (estado === "rechazada" && !motivo) {
        return res.status(400).json({
          error: "Debe ingresar un motivo de rechazo",
        });
      }

      const supervisor = await obtenerSupervisorActivo(req.usuario.dni);

      if (!supervisor) {
        return res.status(403).json({
          error: "La cuenta de supervisor está desactivada o no existe",
        });
      }

      client = await pool.connect();

      await client.query("BEGIN");
      transaccionIniciada = true;

      const vacacionesResult = await client.query(
        `SELECT *
         FROM vacaciones
         WHERE id = $1
         FOR UPDATE`,
        [id]
      );

      if (vacacionesResult.rows.length === 0) {
        await client.query("ROLLBACK");
        transaccionIniciada = false;

        return res.status(404).json({
          error: "Solicitud de vacaciones no encontrada",
        });
      }

      const vacaciones = vacacionesResult.rows[0];

      if (vacaciones.estado !== "solicitada") {
        await client.query("ROLLBACK");
        transaccionIniciada = false;

        return res.status(409).json({
          error: `La solicitud ya fue procesada. Estado actual: ${vacaciones.estado}`,
        });
      }

      // Si se rechaza, no se descuentan días.
      if (estado === "rechazada") {
        const rechazo = await client.query(
          `UPDATE vacaciones
           SET estado = 'rechazada',
               motivo_rechazo = $1,
               aprobado_por = $2,
               aprobado_en = NOW()
           WHERE id = $3
           RETURNING *`,
          [motivo, supervisor.nombre, id]
        );

        await client.query("COMMIT");
        transaccionIniciada = false;

        return res.json({
          success: true,
          mensaje: "Solicitud de vacaciones rechazada",
          vacaciones: rechazo.rows[0],
        });
      }

      const dias = Number(vacaciones.dias_corridos);

      if (!Number.isInteger(dias) || dias <= 0) {
        await client.query("ROLLBACK");
        transaccionIniciada = false;

        return res.status(400).json({
          error: "La solicitud no tiene una cantidad válida de días",
        });
      }

      const trabajadorResult = await client.query(
        `SELECT dni, nombre, dias_vacaciones_disponibles
         FROM trabajadores
         WHERE dni = $1
         FOR UPDATE`,
        [vacaciones.dni]
      );

      if (trabajadorResult.rows.length === 0) {
        await client.query("ROLLBACK");
        transaccionIniciada = false;

        return res.status(404).json({
          error: "Trabajador no encontrado",
        });
      }

      const trabajador = trabajadorResult.rows[0];
      const saldo = Number(trabajador.dias_vacaciones_disponibles);

      if (!Number.isFinite(saldo) || saldo < dias) {
        await client.query("ROLLBACK");
        transaccionIniciada = false;

        return res.status(409).json({
          error: "El trabajador no tiene suficientes días de vacaciones",
          dias_solicitados: dias,
          dias_disponibles: Number.isFinite(saldo) ? saldo : null,
        });
      }

      const descuento = await client.query(
        `UPDATE trabajadores
         SET dias_vacaciones_disponibles =
             dias_vacaciones_disponibles - $1
         WHERE dni = $2
         RETURNING dni, nombre, dias_vacaciones_disponibles`,
        [dias, vacaciones.dni]
      );

      const aprobacion = await client.query(
        `UPDATE vacaciones
         SET estado = 'aprobada',
             motivo_rechazo = NULL,
             aprobado_por = $1,
             aprobado_en = NOW()
         WHERE id = $2
         RETURNING *`,
        [supervisor.nombre, id]
      );

      await client.query("COMMIT");
      transaccionIniciada = false;

      res.json({
        success: true,
        mensaje: "Vacaciones aprobadas y días descontados correctamente",
        vacaciones: aprobacion.rows[0],
        trabajador: descuento.rows[0],
        dias_descontados: dias,
      });
    } catch (error) {
      if (client && transaccionIniciada) {
        try {
          await client.query("ROLLBACK");
        } catch (rollbackError) {
          console.error("Error al revertir transacción:", rollbackError);
        }
      }

      console.error("Error al procesar vacaciones:", error);

      res.status(500).json({
        error: "No se pudo procesar la solicitud",
      });
    } finally {
      if (client) {
        client.release();
      }
    }
  }
);

// ==========================================
// 9. AUTOMATIZACIÓN HSEC DIARIA
// ==========================================
// Deshabilita trabajadores cuando el examen médico o la inducción
// ya vencieron. Los documentos con fecha NULL no se consideran vigentes.
// No reactiva trabajadores automáticamente.

async function actualizarHabilitacionHSEC() {
  try {
    const result = await pool.query(
      `UPDATE trabajadores
       SET habilitado = FALSE
       WHERE habilitado = TRUE
         AND (
           (
             examen_medico_vence IS NOT NULL
             AND examen_medico_vence <
                 (NOW() AT TIME ZONE 'America/Santiago')::date
           )
           OR
           (
             induccion_vence IS NOT NULL
             AND induccion_vence <
                 (NOW() AT TIME ZONE 'America/Santiago')::date
           )
         )
       RETURNING dni`
    );

    console.log(
      `[HSEC] Revisión completada. Trabajadores deshabilitados: ${result.rowCount}`
    );
  } catch (error) {
    console.error("[HSEC] Error en la revisión automática:", error);
  }
}

// Ejecutar al iniciar para recuperar vencimientos ocurridos mientras
// el servidor estaba detenido.
actualizarHabilitacionHSEC();

// Ejecutar todos los días a medianoche, hora de Chile.
cron.schedule(
  "0 0 * * *",
  actualizarHabilitacionHSEC,
  { timezone: "America/Santiago" }
);

// ==========================================
// 10. MANEJO DE ERRORES DE ARCHIVOS
// ==========================================

app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({
        error: "El PDF supera el límite de 5 MB",
      });
    }
  }

  if (error) {
    return res.status(400).json({
      error: error.message || "Error al procesar el archivo",
    });
  }

  next();
});

// ==========================================
// 11. INICIAR SERVIDOR
// ==========================================

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(
    `Servidor HRMS Minera Cordillera corriendo en puerto ${PORT}`
  );
});
