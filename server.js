const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();

// 1. Configuración de CORS total
app.use(cors({ origin: '*' }));
app.use(express.json());

// 2. Conexión a la base de datos Supabase
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// -------------------------------------------------------------
// RUTAS DE LA API (Endpoints)
// -------------------------------------------------------------

// Ping de Calentamiento / Healthcheck
app.get('/api/ping', (req, res) => {
    res.json({ estado: "OK", mensaje: "Servidor HRMS activo", timestamp: new Date() });
});

// HU-01 & HU-02: Validación de Garita (< 1.5s)
app.post('/api/garita/validar', async (req, res) => {
    const { rut, hash_biometrico } = req.body;
    try {
        const query = `
            SELECT t.rut, t.nombre, t.empresa, a.examen_medico_vigente, a.estado_acreditacion
            FROM trabajadores t
            LEFT JOIN acreditaciones_hsec a ON t.rut = a.rut_trabajador
            WHERE t.rut = $1 OR t.hash_biometrico = $2
        `;
        const result = await pool.query(query, [rut || '', hash_biometrico || '']);

        if (result.rows.length === 0) {
            return res.status(404).json({ autorizado: false, motivo: "Trabajador no encontrado en el sistema" });
        }

        const user = result.rows[0];
        const autorizado = (user.estado_acreditacion === 'Aprobado' && user.examen_medico_vigente === true);
        const motivo = autorizado ? "Acceso Permitido" : "Rechazado por HSEC (Examen vencido o no acreditado)";

        res.json({
            autorizado,
            trabajador: `${user.nombre} (${user.empresa})`,
            rut: user.rut,
            motivo
        });
    } catch (err) {
        console.error("Error en garita:", err);
        res.status(500).json({ error: "Error interno al validar en garita" });
    }
});

// HU-04: Subida de Documentos Contratistas (Validación <= 5MB)
app.post('/api/contratistas/subir-documento', (req, res) => {
    const { rut_trabajador, nombre_archivo, peso_mb } = req.body;

    if (peso_mb > 5) {
        return res.status(400).json({ 
            exito: false, 
            mensaje: "El archivo excede el tamaño máximo permitido de 5 MB." 
        });
    }

    res.json({ 
        exito: true, 
        mensaje: `Documento '${nombre_archivo}' recibido correctamente para el RUT ${rut_trabajador}.`,
        notificado_hsec: true
    });
});

// HU-03: Solicitud de Vacaciones (App Móvil - <= 3 toques)
app.post('/api/trabajadores/solicitar-permiso', async (req, res) => {
    const { rut_trabajador, dias_solicitados } = req.body;
    try {
        const checkSaldo = await pool.query('SELECT saldo_vacaciones FROM trabajadores WHERE rut = $1', [rut_trabajador]);
        
        if (checkSaldo.rows.length === 0) {
            return res.status(404).json({ exito: false, mensaje: "Trabajador no encontrado" });
        }

        const saldoActual = checkSaldo.rows[0].saldo_vacaciones;
        if (dias_solicitados > saldoActual) {
            return res.status(400).json({ exito: false, mensaje: "Saldo insuficiente de días" });
        }

        const updateResult = await pool.query(
            `UPDATE trabajadores SET saldo_vacaciones = saldo_vacaciones - $1 WHERE rut = $2 RETURNING saldo_vacaciones`,
            [dias_solicitados, rut_trabajador]
        );

        res.json({ 
            exito: true, 
            mensaje: "Permiso aprobado automáticamente", 
            nuevo_saldo: updateResult.rows[0].saldo_vacaciones 
        });
    } catch (err) {
        console.error("Error en vacaciones:", err);
        res.status(500).json({ error: "Error al procesar la solicitud de vacaciones" });
    }
});

// -------------------------------------------------------------
// ARRANQUE DEL SERVIDOR
// -------------------------------------------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`🚀 Servidor backend corriendo en puerto ${PORT}`));