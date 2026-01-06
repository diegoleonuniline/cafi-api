// ============================================
// GASTOS ROUTES - CAFI POS
// Agregar a routes/index.js o crear routes/gastos.js
// ============================================

const express = require('express');
const router = express.Router();

// GET /api/gastos/:empresaId - Listar gastos con filtros y paginación
router.get('/gastos/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        const { desde, hasta, categoria, estado, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        let where = 'g.empresa_id = ? AND g.activo = "Y"';
        const params = [empresaId];
        
        if (desde) {
            where += ' AND g.fecha >= ?';
            params.push(desde);
        }
        if (hasta) {
            where += ' AND g.fecha <= ?';
            params.push(hasta);
        }
        if (categoria) {
            where += ' AND g.categoria_gasto_id = ?';
            params.push(categoria);
        }
        if (estado) {
            where += ' AND g.estado = ?';
            params.push(estado);
        }
        
        // Contar total
        const [countResult] = await db.query(
            `SELECT COUNT(*) as total FROM gastos g WHERE ${where}`,
            params
        );
        const total = countResult[0].total;
        
        // Obtener registros
        const [gastos] = await db.query(`
            SELECT g.*,
                   cg.nombre as categoria_nombre,
                   co.nombre as concepto_nombre,
                   mp.nombre as metodo_pago_nombre,
                   s.nombre as sucursal_nombre
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            LEFT JOIN conceptos_gasto co ON g.concepto_gasto_id = co.concepto_gasto_id
            LEFT JOIN metodos_pago mp ON g.metodo_pago_id = mp.metodo_pago_id
            LEFT JOIN sucursales s ON g.sucursal_id = s.sucursal_id
            WHERE ${where}
            ORDER BY g.fecha DESC, g.gasto_id DESC
            LIMIT ? OFFSET ?
        `, [...params, parseInt(limit), parseInt(offset)]);
        
        // Totales del período
        const [totalesResult] = await db.query(`
            SELECT 
                COALESCE(SUM(subtotal), 0) as subtotal,
                COALESCE(SUM(iva), 0) as iva,
                COALESCE(SUM(total), 0) as total
            FROM gastos g
            WHERE ${where}
        `, params);
        
        res.json({
            success: true,
            gastos,
            total,
            totales: totalesResult[0]
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// GET /api/gastos/kpis/:empresaId - KPIs del dashboard
router.get('/gastos/kpis/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        
        // Gastos hoy
        const [hoyResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total
            FROM gastos
            WHERE empresa_id = ? AND activo = 'Y' AND DATE(fecha) = CURDATE()
        `, [empresaId]);
        
        // Gastos semana
        const [semanaResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total
            FROM gastos
            WHERE empresa_id = ? AND activo = 'Y' 
            AND YEARWEEK(fecha, 1) = YEARWEEK(CURDATE(), 1)
        `, [empresaId]);
        
        // Gastos mes
        const [mesResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total,
                   COUNT(*) as registros
            FROM gastos
            WHERE empresa_id = ? AND activo = 'Y'
            AND YEAR(fecha) = YEAR(CURDATE()) 
            AND MONTH(fecha) = MONTH(CURDATE())
        `, [empresaId]);
        
        // Por categoría (mes actual)
        const [porCategoria] = await db.query(`
            SELECT cg.nombre as categoria, COALESCE(SUM(g.total), 0) as total
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            WHERE g.empresa_id = ? AND g.activo = 'Y'
            AND YEAR(g.fecha) = YEAR(CURDATE()) 
            AND MONTH(g.fecha) = MONTH(CURDATE())
            GROUP BY g.categoria_gasto_id
            ORDER BY total DESC
            LIMIT 8
        `, [empresaId]);
        
        // Últimos 7 días
        const [porDia] = await db.query(`
            SELECT DATE_FORMAT(fecha, '%d/%m') as dia, COALESCE(SUM(total), 0) as total
            FROM gastos
            WHERE empresa_id = ? AND activo = 'Y'
            AND fecha >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            GROUP BY DATE(fecha)
            ORDER BY fecha ASC
        `, [empresaId]);
        
        res.json({
            success: true,
            hoy: hoyResult[0].total,
            semana: semanaResult[0].total,
            mes: mesResult[0].total,
            registros: mesResult[0].registros,
            porCategoria,
            porDia
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// GET /api/gastos/detalle/:id - Detalle de un gasto
router.get('/gastos/detalle/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        const [gastos] = await db.query(`
            SELECT g.*,
                   cg.nombre as categoria_nombre,
                   co.nombre as concepto_nombre,
                   mp.nombre as metodo_pago_nombre,
                   cb.banco as cuenta_nombre,
                   s.nombre as sucursal_nombre,
                   p.nombre_comercial as proveedor_nombre_catalogo
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            LEFT JOIN conceptos_gasto co ON g.concepto_gasto_id = co.concepto_gasto_id
            LEFT JOIN metodos_pago mp ON g.metodo_pago_id = mp.metodo_pago_id
            LEFT JOIN cuentas_bancarias cb ON g.cuenta_bancaria_id = cb.cuenta_id
            LEFT JOIN sucursales s ON g.sucursal_id = s.sucursal_id
            LEFT JOIN proveedores p ON g.proveedor_id = p.proveedor_id
            WHERE g.gasto_id = ?
        `, [id]);
        
        if (!gastos.length) {
            return res.status(404).json({ success: false, error: 'Gasto no encontrado' });
        }
        
        res.json({ success: true, gasto: gastos[0] });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST /api/gastos - Crear gasto
router.post('/gastos', async (req, res) => {
    try {
        const {
            empresa_id, sucursal_id, categoria_gasto_id, concepto_gasto_id,
            fecha, numero_documento, descripcion,
            proveedor_id, proveedor_nombre,
            subtotal, iva, isr_retenido, iva_retenido, total,
            metodo_pago_id, cuenta_bancaria_id, referencia_pago,
            tiene_factura, uuid_factura, estado
        } = req.body;
        
        const usuario = req.usuario || {};
        
        const [result] = await db.query(`
            INSERT INTO gastos (
                empresa_id, sucursal_id, categoria_gasto_id, concepto_gasto_id,
                fecha, numero_documento, descripcion,
                proveedor_id, proveedor_nombre,
                subtotal, iva, isr_retenido, iva_retenido, total,
                metodo_pago_id, cuenta_bancaria_id, referencia_pago,
                tiene_factura, uuid_factura, estado, usuario_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            empresa_id, sucursal_id || null, categoria_gasto_id || null, concepto_gasto_id || null,
            fecha, numero_documento, descripcion,
            proveedor_id || null, proveedor_nombre,
            subtotal || 0, iva || 0, isr_retenido || 0, iva_retenido || 0, total || 0,
            metodo_pago_id || null, cuenta_bancaria_id || null, referencia_pago,
            tiene_factura || 'N', uuid_factura, estado || 'PAGADO', usuario.usuario_id || null
        ]);
        
        res.json({ success: true, gasto_id: result.insertId });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// PUT /api/gastos/:id - Actualizar gasto
router.put('/gastos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const {
            sucursal_id, categoria_gasto_id, concepto_gasto_id,
            fecha, numero_documento, descripcion,
            proveedor_id, proveedor_nombre,
            subtotal, iva, isr_retenido, iva_retenido, total,
            metodo_pago_id, cuenta_bancaria_id, referencia_pago,
            tiene_factura, uuid_factura, estado
        } = req.body;
        
        await db.query(`
            UPDATE gastos SET
                sucursal_id = ?,
                categoria_gasto_id = ?,
                concepto_gasto_id = ?,
                fecha = ?,
                numero_documento = ?,
                descripcion = ?,
                proveedor_id = ?,
                proveedor_nombre = ?,
                subtotal = ?,
                iva = ?,
                isr_retenido = ?,
                iva_retenido = ?,
                total = ?,
                metodo_pago_id = ?,
                cuenta_bancaria_id = ?,
                referencia_pago = ?,
                tiene_factura = ?,
                uuid_factura = ?,
                estado = ?
            WHERE gasto_id = ?
        `, [
            sucursal_id || null, categoria_gasto_id || null, concepto_gasto_id || null,
            fecha, numero_documento, descripcion,
            proveedor_id || null, proveedor_nombre,
            subtotal || 0, iva || 0, isr_retenido || 0, iva_retenido || 0, total || 0,
            metodo_pago_id || null, cuenta_bancaria_id || null, referencia_pago,
            tiene_factura || 'N', uuid_factura, estado || 'PAGADO',
            id
        ]);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// DELETE /api/gastos/:id - Eliminar (soft delete)
router.delete('/gastos/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        await db.query(`UPDATE gastos SET activo = 'N' WHERE gasto_id = ?`, [id]);
        
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// GET /api/gastos/exportar/:empresaId - Exportar a Excel
router.get('/gastos/exportar/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        const { desde, hasta } = req.query;
        
        let where = 'g.empresa_id = ? AND g.activo = "Y"';
        const params = [empresaId];
        
        if (desde) {
            where += ' AND g.fecha >= ?';
            params.push(desde);
        }
        if (hasta) {
            where += ' AND g.fecha <= ?';
            params.push(hasta);
        }
        
        const [gastos] = await db.query(`
            SELECT 
                g.fecha,
                g.numero_documento,
                cg.nombre as categoria,
                co.nombre as concepto,
                g.descripcion,
                g.proveedor_nombre,
                g.subtotal,
                g.iva,
                g.total,
                g.estado,
                CASE WHEN g.tiene_factura = 'Y' THEN 'Sí' ELSE 'No' END as factura
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            LEFT JOIN conceptos_gasto co ON g.concepto_gasto_id = co.concepto_gasto_id
            WHERE ${where}
            ORDER BY g.fecha DESC
        `, params);
        
        // Generar CSV simple
        let csv = 'Fecha,Documento,Categoría,Concepto,Descripción,Proveedor,Subtotal,IVA,Total,Estado,Factura\n';
        
        gastos.forEach(g => {
            csv += `${g.fecha},${g.numero_documento || ''},${g.categoria || ''},${g.concepto || ''},"${(g.descripcion || '').replace(/"/g, '""')}",${g.proveedor_nombre || ''},${g.subtotal},${g.iva},${g.total},${g.estado},${g.factura}\n`;
        });
        
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=gastos_${desde}_${hasta}.csv`);
        res.send('\uFEFF' + csv); // BOM para Excel
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

module.exports = router;
