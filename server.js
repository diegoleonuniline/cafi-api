require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// CORS
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.options('*', cors());
app.use(express.json());

// DB Pool
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

// Helpers
const generarID = (prefijo) => `${prefijo}-${uuidv4().substring(0, 8).toUpperCase()}`;

// ==================== AUTH ====================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { usuario, email, password } = req.body;
    const loginEmail = email || usuario;
    
    if (!loginEmail || !password) {
      return res.status(400).json({ success: false, error: 'Email y contraseña requeridos' });
    }
    
    const [usuarios] = await db.query(`
      SELECT u.*, e.nombre as empresa_nombre, s.nombre as sucursal_nombre,
             e.activa as empresa_activa, e.fecha_vencimiento,
             a.almacen_id, a.nombre as almacen_nombre
      FROM usuarios u
      JOIN empresas e ON u.empresa_id = e.empresa_id
      JOIN sucursales s ON u.sucursal_id = s.sucursal_id
      LEFT JOIN almacenes a ON a.sucursal_id = s.sucursal_id AND a.es_punto_venta = 'Y'
      WHERE u.email = ? AND u.activo = 'Y'
    `, [loginEmail.toLowerCase().trim()]);
    
    if (usuarios.length === 0) {
      return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
    }
    
    const user = usuarios[0];
    
    if (user.contrasena !== password) {
      return res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
    }
    
    if (user.empresa_activa !== 'Y') {
      return res.status(401).json({ success: false, error: 'Empresa inactiva' });
    }
    
    const token = jwt.sign({
      usuario_id: user.usuario_id,
      email: user.email,
      nombre: user.nombre,
      rol: user.rol,
      empresa_id: user.empresa_id,
      sucursal_id: user.sucursal_id,
      almacen_id: user.almacen_id
    }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    await db.query('UPDATE usuarios SET ultimo_acceso = NOW() WHERE usuario_id = ?', [user.usuario_id]);
    
    res.json({
      success: true,
      token,
      usuario: {
        id: user.usuario_id,
        email: user.email,
        nombre: user.nombre,
        rol: user.rol,
        empresa_id: user.empresa_id,
        empresa_nombre: user.empresa_nombre,
        sucursal_id: user.sucursal_id,
        sucursal_nombre: user.sucursal_nombre,
        almacen_id: user.almacen_id
      }
    });
    
  } catch (e) {
    console.error('Error login:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/auth/verificar', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ success: false, error: 'Token requerido' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ success: true, usuario: decoded });
  } catch (e) {
    res.status(401).json({ success: false, error: 'Token inválido' });
  }
});

// ==================== IMPUESTOS ====================

app.get('/api/impuestos/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM impuestos WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, impuestos: rows, data: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});


//  obtener impuestos de un producto

app.get('/api/productos/:productoID/impuestos', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT i.* FROM producto_impuesto pi
      JOIN impuestos i ON pi.impuesto_id = i.impuesto_id
      WHERE pi.producto_id = ?
    `, [req.params.productoID]);
    res.json({ success: true, impuestos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});



// ==================== CATEGORÍAS ====================

app.get('/api/categorias/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM categorias WHERE empresa_id = ? ORDER BY orden, nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, categorias: rows, data: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/categorias', async (req, res) => {
  try {
    const { empresa_id, nombre, color, icono, orden } = req.body;
    const id = generarID('CAT');
    await db.query(
      'INSERT INTO categorias (categoria_id, empresa_id, nombre, color, icono, orden) VALUES (?, ?, ?, ?, ?, ?)',
      [id, empresa_id, nombre, color || '#3498db', icono || 'fa-folder', orden || 0]
    );
    res.json({ success: true, id, categoria_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/categorias/:id', async (req, res) => {
  try {
    const { nombre, color, icono, orden, activo } = req.body;
    await db.query(
      'UPDATE categorias SET nombre=?, color=?, icono=?, orden=?, activo=? WHERE categoria_id=?',
      [nombre, color, icono, orden, activo || 'Y', req.params.id]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/categorias/:id', async (req, res) => {
  try {
    await db.query('UPDATE categorias SET activo = "N" WHERE categoria_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== PRODUCTOS ====================

app.get('/api/productos/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT p.*, c.nombre as categoria_nombre,
             COALESCE(imp.tasa_total, 0) as tasa_impuesto,
             imp.impuestos_detalle
      FROM productos p
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      LEFT JOIN (
        SELECT pi.producto_id,
               SUM(i.valor) as tasa_total,
               GROUP_CONCAT(CONCAT(i.nombre, ':', i.valor) SEPARATOR ', ') as impuestos_detalle
        FROM producto_impuesto pi
        JOIN impuestos i ON pi.impuesto_id = i.impuesto_id AND i.activo = 'Y' AND i.aplica_ventas = 'Y'
        GROUP BY pi.producto_id
      ) imp ON p.producto_id = imp.producto_id
      WHERE p.empresa_id = ?
      ORDER BY p.nombre
    `, [req.params.empresaID]);
    
    rows.forEach(p => {
      const tasa = parseFloat(p.tasa_impuesto) || 0;
      const precio = parseFloat(p.precio1) || 0;
      
      if (p.precio_incluye_impuesto === 'Y') {
        p.precio_venta = precio;
      } else {
        p.precio_venta = precio * (1 + tasa / 100);
      }
      p.precio_venta = Math.round(p.precio_venta * 100) / 100;
    });
    
    res.json({ success: true, data: rows, productos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/productos', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const d = req.body;
    const id = generarID('PROD');
    
    await conn.query(`
      INSERT INTO productos (
        producto_id, empresa_id, categoria_id, codigo_barras, codigo_interno, codigo_sat,
        nombre, nombre_corto, nombre_pos, nombre_ticket, descripcion,
        tipo, imagen_url,
        unidad_compra, unidad_venta, factor_conversion,
        unidad_inventario_id, factor_venta,
        costo_compra, costo, precio1, precio2, precio3, precio4, precio_minimo,
        precio_incluye_impuesto,
        stock_minimo, stock_maximo, punto_reorden, ubicacion_almacen,
        maneja_lotes, maneja_caducidad, maneja_series, dias_caducidad,
        es_inventariable, es_vendible, es_comprable, mostrar_pos,
        permite_descuento, descuento_maximo,
        color_pos, orden_pos, tecla_rapida, notas_internas, activo
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [
      id, d.empresa_id, d.categoria_id || null, d.codigo_barras, d.codigo_interno, d.codigo_sat,
      d.nombre, d.nombre_corto, d.nombre_pos, d.nombre_ticket, d.descripcion,
      d.tipo || 'PRODUCTO', d.imagen_url,
      d.unidad_compra || 'PZ', d.unidad_venta || 'PZ', d.factor_conversion || 1,
      d.unidad_inventario_id || 'PZ', d.factor_venta || 1,
      d.costo_compra || 0, d.costo || 0, d.precio1 || 0, d.precio2 || 0, d.precio3 || 0, d.precio4 || 0, d.precio_minimo || 0,
      d.precio_incluye_impuesto || 'Y',
      d.stock_minimo || 0, d.stock_maximo || 0, d.punto_reorden || 0, d.ubicacion_almacen,
      d.maneja_lotes || 'N', d.maneja_caducidad || 'N', d.maneja_series || 'N', d.dias_caducidad || 0,
      d.es_inventariable || 'Y', d.es_vendible || 'Y', d.es_comprable || 'Y', d.mostrar_pos || 'Y',
      d.permite_descuento || 'Y', d.descuento_maximo || 100,
      d.color_pos, d.orden_pos || 0, d.tecla_rapida, d.notas_internas
    ]);
    
    // Insertar impuestos si vienen
    if (d.impuestos && d.impuestos.length > 0) {
      for (const impuesto_id of d.impuestos) {
        await conn.query(
          'INSERT INTO producto_impuesto (producto_id, impuesto_id) VALUES (?, ?)',
          [id, impuesto_id]
        );
      }
    }
    
    await conn.commit();
    res.json({ success: true, id, producto_id: id });
  } catch (e) {
    await conn.rollback();
    console.error('Error crear producto:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

app.put('/api/productos/:id', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const d = req.body;
    
    await conn.query(`
      UPDATE productos SET 
        categoria_id=?, codigo_barras=?, codigo_interno=?, codigo_sat=?,
        nombre=?, nombre_corto=?, nombre_pos=?, nombre_ticket=?, descripcion=?,
        tipo=?, imagen_url=?,
        unidad_compra=?, unidad_venta=?, factor_conversion=?, 
        unidad_inventario_id=?, factor_venta=?,
        costo_compra=?, costo=?, precio1=?, precio2=?, precio3=?, precio4=?, precio_minimo=?,
        precio_incluye_impuesto=?,
        stock_minimo=?, stock_maximo=?, punto_reorden=?, ubicacion_almacen=?,
        maneja_lotes=?, maneja_caducidad=?, maneja_series=?, dias_caducidad=?,
        es_inventariable=?, es_vendible=?, es_comprable=?, mostrar_pos=?,
        permite_descuento=?, descuento_maximo=?,
        color_pos=?, orden_pos=?, tecla_rapida=?, notas_internas=?, activo=?
      WHERE producto_id=?
    `, [
      d.categoria_id, d.codigo_barras, d.codigo_interno, d.codigo_sat,
      d.nombre, d.nombre_corto, d.nombre_pos, d.nombre_ticket, d.descripcion,
      d.tipo, d.imagen_url,
      d.unidad_compra, d.unidad_venta, d.factor_conversion,
      d.unidad_inventario_id, d.factor_venta,
      d.costo_compra, d.costo, d.precio1, d.precio2, d.precio3, d.precio4, d.precio_minimo,
      d.precio_incluye_impuesto,
      d.stock_minimo, d.stock_maximo, d.punto_reorden, d.ubicacion_almacen,
      d.maneja_lotes, d.maneja_caducidad, d.maneja_series, d.dias_caducidad,
      d.es_inventariable, d.es_vendible, d.es_comprable, d.mostrar_pos,
      d.permite_descuento, d.descuento_maximo,
      d.color_pos, d.orden_pos, d.tecla_rapida, d.notas_internas, d.activo || 'Y',
      req.params.id
    ]);
    
    // Actualizar impuestos si vienen
    if (d.impuestos !== undefined) {
      await conn.query('DELETE FROM producto_impuesto WHERE producto_id = ?', [req.params.id]);
      if (d.impuestos && d.impuestos.length > 0) {
        for (const impuesto_id of d.impuestos) {
          await conn.query(
            'INSERT INTO producto_impuesto (producto_id, impuesto_id) VALUES (?, ?)',
            [req.params.id, impuesto_id]
          );
        }
      }
    }
    
    await conn.commit();
    res.json({ success: true });
  } catch (e) {
    await conn.rollback();
    console.error('Error actualizar producto:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

app.delete('/api/productos/:id', async (req, res) => {
  try {
    await db.query('UPDATE productos SET activo = "N" WHERE producto_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== CLIENTES ====================

app.get('/api/clientes/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM clientes WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, clientes: rows, data: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/clientes/detalle/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM clientes WHERE cliente_id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'No encontrado' });
    res.json({ success: true, data: rows[0] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/clientes', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('CLI');
    await db.query(`
      INSERT INTO clientes (
        cliente_id, empresa_id, nombre, telefono, email, direccion,
        rfc, tipo_precio, permite_credito, limite_credito, activo
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [
      id, d.empresa_id, d.nombre, d.telefono, d.email, d.direccion,
      d.rfc, d.tipo_precio || 1, d.permite_credito || 'N', d.limite_credito || 0
    ]);
    res.json({ success: true, id, cliente_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/clientes/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE clientes SET 
        nombre=?, telefono=?, email=?, direccion=?, rfc=?,
        tipo_precio=?, permite_credito=?, limite_credito=?, activo=?
      WHERE cliente_id=?
    `, [
      d.nombre, d.telefono, d.email, d.direccion, d.rfc,
      d.tipo_precio, d.permite_credito, d.limite_credito, d.activo || 'Y',
      req.params.id
    ]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/clientes/:id', async (req, res) => {
  try {
    await db.query('UPDATE clientes SET activo = "N" WHERE cliente_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== MÉTODOS DE PAGO ====================

app.get('/api/metodos-pago/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM metodos_pago WHERE empresa_id = ? AND activo = "Y" ORDER BY orden',
      [req.params.empresaID]
    );
    res.json({ success: true, metodos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== POS ====================

app.get('/api/pos/cargar/:empresaID/:sucursalID', async (req, res) => {
  try {
    const { empresaID, sucursalID } = req.params;
    
    const [productos] = await db.query(`
      SELECT p.*, c.nombre as categoria_nombre, c.color as categoria_color,
             COALESCE(inv.stock, 0) as stock,
             COALESCE(imp.tasa_total, 0) as tasa_impuesto
      FROM productos p
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      LEFT JOIN inventario inv ON p.producto_id = inv.producto_id
      LEFT JOIN (
        SELECT pi.producto_id, SUM(i.valor) as tasa_total
        FROM producto_impuesto pi
        JOIN impuestos i ON pi.impuesto_id = i.impuesto_id AND i.activo = 'Y' AND i.aplica_ventas = 'Y'
        GROUP BY pi.producto_id
      ) imp ON p.producto_id = imp.producto_id
      WHERE p.empresa_id = ? AND p.activo = 'Y'
      ORDER BY p.nombre
    `, [empresaID]);
    
    productos.forEach(p => {
      const tasa = parseFloat(p.tasa_impuesto) || 0;
      const factor = p.precio_incluye_impuesto === 'Y' ? 1 : (1 + tasa / 100);
      
      p.precio_venta = Math.round((parseFloat(p.precio1) || 0) * factor * 100) / 100;
      p.precio_venta2 = Math.round((parseFloat(p.precio2) || 0) * factor * 100) / 100;
      p.precio_venta3 = Math.round((parseFloat(p.precio3) || 0) * factor * 100) / 100;
      p.precio_venta4 = Math.round((parseFloat(p.precio4) || 0) * factor * 100) / 100;
    });
    
    const [categorias] = await db.query(
      'SELECT * FROM categorias WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
      [empresaID]
    );
    
    const [clientes] = await db.query(
      'SELECT * FROM clientes WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
      [empresaID]
    );
    
    const [metodos] = await db.query(
      'SELECT * FROM metodos_pago WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
      [empresaID]
    );
    
    res.json({ success: true, productos, categorias, clientes, metodos });
  } catch (e) {
    console.error('Error cargando POS:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== VENTAS ====================

app.get('/api/ventas/resumen/:empresaID/:sucursalID', async (req, res) => {
  try {
    const { empresaID, sucursalID } = req.params;
    const hoy = new Date().toISOString().split('T')[0];
    
    const [resumen] = await db.query(`
      SELECT 
        COALESCE(SUM(total), 0) as total_hoy,
        COUNT(*) as tickets_hoy
      FROM ventas 
      WHERE empresa_id = ? 
        AND sucursal_id = ?
        AND DATE(fecha_hora) = ?
        AND estatus = 'PAGADA'
    `, [empresaID, sucursalID, hoy]);
    
    const [ultimas] = await db.query(`
      SELECT v.venta_id, v.folio, v.total, v.fecha_hora, v.estatus,
             c.nombre as cliente_nombre
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      WHERE v.empresa_id = ? AND v.sucursal_id = ?
      ORDER BY v.fecha_hora DESC
      LIMIT 10
    `, [empresaID, sucursalID]);
    
    res.json({
      success: true,
      total_hoy: resumen[0].total_hoy,
      tickets_hoy: resumen[0].tickets_hoy,
      ultimas
    });
  } catch (e) {
    console.error('Error resumen ventas:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/ventas/:empresaID', async (req, res) => {
  try {
    const { desde, hasta, sucursal } = req.query;
    let query = `
      SELECT v.*, c.nombre as cliente_nombre, u.nombre as usuario_nombre,
        (SELECT COUNT(*) FROM detalle_venta WHERE venta_id = v.venta_id) as num_productos
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      LEFT JOIN usuarios u ON v.usuario_id = u.usuario_id
      WHERE v.empresa_id = ?
    `;
    const params = [req.params.empresaID];
    
    if (desde) {
      query += ' AND DATE(v.fecha_hora) >= ?';
      params.push(desde);
    }
    if (hasta) {
      query += ' AND DATE(v.fecha_hora) <= ?';
      params.push(hasta);
    }
    if (sucursal) {
      query += ' AND v.sucursal_id = ?';
      params.push(sucursal);
    }
    
    query += ' ORDER BY v.fecha_hora DESC LIMIT 500';
    
    const [ventas] = await db.query(query, params);
    res.json({ success: true, ventas });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/ventas/detalle/:id', async (req, res) => {
  try {
    const [ventas] = await db.query(`
      SELECT v.*, c.nombre as cliente_nombre, u.nombre as usuario_nombre
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      LEFT JOIN usuarios u ON v.usuario_id = u.usuario_id
      WHERE v.venta_id = ?
    `, [req.params.id]);
    
    if (ventas.length === 0) {
      return res.status(404).json({ success: false, error: 'Venta no encontrada' });
    }
    
    const [productos] = await db.query(`
      SELECT d.*, p.nombre as producto_nombre, p.unidad_venta as unidad
      FROM detalle_venta d
      LEFT JOIN productos p ON d.producto_id = p.producto_id
      WHERE d.venta_id = ?
    `, [req.params.id]);
    
    res.json({ success: true, venta: ventas[0], productos });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/ventas', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const d = req.body;
    const ventaId = generarID('VTA');
    
    const [folioRes] = await conn.query(
      'SELECT COALESCE(MAX(folio), 0) + 1 as siguiente FROM ventas WHERE empresa_id = ? AND serie = ?',
      [d.empresa_id, 'A']
    );
    const folio = folioRes[0].siguiente;
    
    await conn.query(`
      INSERT INTO ventas (
        venta_id, empresa_id, sucursal_id, almacen_id, usuario_id, cliente_id,
        tipo, serie, folio, fecha_hora, tipo_venta, tipo_precio,
        subtotal, total, pagado, cambio, estatus
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'A', ?, NOW(), ?, ?, ?, ?, ?, ?, 'PAGADA')
    `, [
      ventaId, d.empresa_id, d.sucursal_id, d.almacen_id, d.usuario_id, d.cliente_id,
      d.tipo || 'VENTA', folio, d.tipo_venta || 'CONTADO', d.tipo_precio || 1,
      d.subtotal, d.total, d.pagado, d.cambio
    ]);
    
    for (const item of d.items) {
      const detalleId = generarID('DET');
      await conn.query(`
        INSERT INTO detalle_venta (
          detalle_id, venta_id, producto_id, descripcion, cantidad, unidad_id,
          precio_lista, precio_unitario, subtotal
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        detalleId, ventaId, item.producto_id, item.descripcion, item.cantidad,
        item.unidad_id || 'PZ', item.precio_unitario, item.precio_unitario, item.subtotal
      ]);
    }
    
    if (d.pagos && d.pagos.length > 0) {
      for (const pago of d.pagos) {
        const pagoId = generarID('PAG');
        await conn.query(`
          INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, metodo_pago_id, monto, usuario_id)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [pagoId, d.empresa_id, d.sucursal_id, ventaId, pago.metodo_pago_id, pago.monto, d.usuario_id]);
      }
    }
    
    await conn.commit();
    res.json({ success: true, venta_id: ventaId, folio: folio });
  } catch (e) {
    await conn.rollback();
    console.error('Error crear venta:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

app.put('/api/ventas/cancelar/:id', async (req, res) => {
  try {
    const { motivo_cancelacion } = req.body;
    await db.query(`
      UPDATE ventas SET 
        estatus = 'CANCELADA',
        motivo_cancelacion = ?
      WHERE venta_id = ?
    `, [motivo_cancelacion, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== HEALTH ====================

app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (e) {
    res.json({ status: 'ok', db: 'error', error: e.message });
  }
});

// ==================== START ====================

app.listen(PORT, () => console.log(`CAFI API puerto ${PORT}`));
