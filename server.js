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

app.get('/api/impuestos/:empresaID/todos', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM impuestos WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, impuestos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/impuestos', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('IMP');
    await db.query(`
      INSERT INTO impuestos (impuesto_id, empresa_id, nombre, tipo, valor, aplica_ventas, aplica_compras, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.nombre, d.tipo || 'PORCENTAJE', d.valor || 0, d.aplica_ventas || 'Y', d.aplica_compras || 'Y']);
    res.json({ success: true, id, impuesto_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/impuestos/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE impuestos SET nombre=?, tipo=?, valor=?, aplica_ventas=?, aplica_compras=?
      WHERE impuesto_id=?
    `, [d.nombre, d.tipo, d.valor, d.aplica_ventas, d.aplica_compras, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/impuestos/:id', async (req, res) => {
  try {
    await db.query('UPDATE impuestos SET activo = "N" WHERE impuesto_id = ?', [req.params.id]);
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

app.get('/api/metodos-pago/:empresaID/todos', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM metodos_pago WHERE empresa_id = ? ORDER BY orden, nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, metodos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/metodos-pago', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('MP');
    await db.query(`
      INSERT INTO metodos_pago (metodo_pago_id, empresa_id, nombre, tipo, icono, clave_sat, requiere_referencia, orden, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.nombre, d.tipo || 'EFECTIVO', d.icono || 'fa-money-bill-wave', d.clave_sat, d.requiere_referencia || 'N', d.orden || 0]);
    res.json({ success: true, id, metodo_pago_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/metodos-pago/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE metodos_pago SET nombre=?, tipo=?, icono=?, clave_sat=?, requiere_referencia=?, orden=?
      WHERE metodo_pago_id=?
    `, [d.nombre, d.tipo, d.icono, d.clave_sat, d.requiere_referencia, d.orden, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/metodos-pago/:id', async (req, res) => {
  try {
    await db.query('UPDATE metodos_pago SET activo = "N" WHERE metodo_pago_id = ?', [req.params.id]);
    res.json({ success: true });
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
               SUM(CASE WHEN pi.tipo = 'PORCENTAJE' THEN pi.valor ELSE 0 END) as tasa_total,
               GROUP_CONCAT(CONCAT(i.nombre, ':', pi.tipo, ':', pi.valor) SEPARATOR ', ') as impuestos_detalle
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

app.get('/api/productos/:productoID/impuestos', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT pi.impuesto_id, i.nombre, pi.tipo, pi.valor
      FROM producto_impuesto pi
      JOIN impuestos i ON pi.impuesto_id = i.impuesto_id
      WHERE pi.producto_id = ?
    `, [req.params.productoID]);
    res.json({ success: true, impuestos: rows });
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
    
    if (d.impuestos && d.impuestos.length > 0) {
      for (const imp of d.impuestos) {
        if (typeof imp === 'object') {
          await conn.query(
            'INSERT INTO producto_impuesto (producto_id, impuesto_id, tipo, valor) VALUES (?, ?, ?, ?)',
            [id, imp.impuesto_id, imp.tipo || 'PORCENTAJE', imp.valor || 0]
          );
        } else {
          await conn.query(
            'INSERT INTO producto_impuesto (producto_id, impuesto_id, tipo, valor) VALUES (?, ?, "PORCENTAJE", 0)',
            [id, imp]
          );
        }
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
    
    if (d.impuestos !== undefined) {
      await conn.query('DELETE FROM producto_impuesto WHERE producto_id = ?', [req.params.id]);
      if (d.impuestos && d.impuestos.length > 0) {
        for (const imp of d.impuestos) {
          if (typeof imp === 'object') {
            await conn.query(
              'INSERT INTO producto_impuesto (producto_id, impuesto_id, tipo, valor) VALUES (?, ?, ?, ?)',
              [req.params.id, imp.impuesto_id, imp.tipo || 'PORCENTAJE', imp.valor || 0]
            );
          } else {
            await conn.query(
              'INSERT INTO producto_impuesto (producto_id, impuesto_id, tipo, valor) VALUES (?, ?, "PORCENTAJE", 0)',
              [req.params.id, imp]
            );
          }
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

// ==================== POS ====================

app.get('/api/pos/cargar/:empresaID/:sucursalID', async (req, res) => {
  try {
    const { empresaID, sucursalID } = req.params;
    
    const [productos] = await db.query(`
      SELECT p.*, c.nombre as categoria_nombre, c.color as categoria_color,
             COALESCE(inv.stock, 0) as stock,
             COALESCE(imp.tasa_total, 0) as tasa_impuesto,
             COALESCE(imp.monto_fijo, 0) as monto_impuesto_fijo
      FROM productos p
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      LEFT JOIN inventario inv ON p.producto_id = inv.producto_id
      LEFT JOIN (
        SELECT pi.producto_id, 
               SUM(CASE WHEN pi.tipo = 'PORCENTAJE' THEN pi.valor ELSE 0 END) as tasa_total,
               SUM(CASE WHEN pi.tipo = 'FIJO' THEN pi.valor ELSE 0 END) as monto_fijo
        FROM producto_impuesto pi
        JOIN impuestos i ON pi.impuesto_id = i.impuesto_id AND i.activo = 'Y' AND i.aplica_ventas = 'Y'
        GROUP BY pi.producto_id
      ) imp ON p.producto_id = imp.producto_id
      WHERE p.empresa_id = ? AND p.activo = 'Y'
      ORDER BY p.nombre
    `, [empresaID]);
    
    productos.forEach(p => {
      const tasa = parseFloat(p.tasa_impuesto) || 0;
      const montoFijo = parseFloat(p.monto_impuesto_fijo) || 0;
      const precio1 = parseFloat(p.precio1) || 0;
      const precio2 = parseFloat(p.precio2) || 0;
      const precio3 = parseFloat(p.precio3) || 0;
      const precio4 = parseFloat(p.precio4) || 0;
      
      if (p.precio_incluye_impuesto === 'Y') {
        p.precio_venta = precio1;
        p.precio_venta2 = precio2;
        p.precio_venta3 = precio3;
        p.precio_venta4 = precio4;
      } else {
        p.precio_venta = Math.round((precio1 * (1 + tasa / 100) + montoFijo) * 100) / 100;
        p.precio_venta2 = Math.round((precio2 * (1 + tasa / 100) + montoFijo) * 100) / 100;
        p.precio_venta3 = Math.round((precio3 * (1 + tasa / 100) + montoFijo) * 100) / 100;
        p.precio_venta4 = Math.round((precio4 * (1 + tasa / 100) + montoFijo) * 100) / 100;
      }
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
      'SELECT * FROM metodos_pago WHERE empresa_id = ? AND activo = "Y" ORDER BY orden, nombre',
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

// POST VENTAS - CON TURNO_ID EN PAGOS
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
        venta_id, empresa_id, sucursal_id, almacen_id, usuario_id, cliente_id, turno_id,
        tipo, serie, folio, fecha_hora, tipo_venta, tipo_precio,
        subtotal, descuento, total, pagado, cambio, estatus
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'A', ?, NOW(), ?, ?, ?, ?, ?, ?, ?, 'PAGADA')
    `, [
      ventaId, d.empresa_id, d.sucursal_id, d.almacen_id, d.usuario_id, d.cliente_id, d.turno_id,
      d.tipo || 'VENTA', folio, d.tipo_venta || 'CONTADO', d.tipo_precio || 1,
      d.subtotal, d.descuento || 0, d.total, d.pagado, d.cambio
    ]);
    
    // DETALLE DE VENTA
    for (const item of d.items) {
      const detalleId = generarID('DET');
      const subtotalItem = item.precio_unitario * item.cantidad;
      const descuentoPct = item.descuento || 0;
      const descuentoMonto = subtotalItem * descuentoPct / 100;
      
      await conn.query(`
        INSERT INTO detalle_venta (
          detalle_id, venta_id, producto_id, descripcion, cantidad, unidad_id,
          precio_lista, precio_unitario, descuento_pct, descuento_monto, subtotal
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `, [
        detalleId, ventaId, item.producto_id, item.descripcion, item.cantidad,
        item.unidad_id || 'PZ', item.precio_unitario, item.precio_unitario, 
        descuentoPct, descuentoMonto, item.subtotal
      ]);
    }
    
    // PAGOS - CON TURNO_ID
    if (d.pagos && d.pagos.length > 0) {
      for (const pago of d.pagos) {
        const pagoId = generarID('PAG');
        await conn.query(`
          INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, turno_id, metodo_pago_id, monto, usuario_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [pagoId, d.empresa_id, d.sucursal_id, ventaId, d.turno_id, pago.metodo_pago_id, pago.monto, d.usuario_id]);
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

// ==================== TURNOS ====================

app.get('/api/turnos/activo/:sucursalID/:usuarioID', async (req, res) => {
  try {
    const { sucursalID } = req.params;
    const [turnos] = await db.query(`
      SELECT t.*, u.nombre as usuario_nombre
      FROM turnos t
      JOIN usuarios u ON t.usuario_id = u.usuario_id
      WHERE t.sucursal_id = ? AND t.estado = 'ABIERTO'
      ORDER BY t.fecha_apertura DESC
      LIMIT 1
    `, [sucursalID]);
    
    if (turnos.length > 0) {
      res.json({ success: true, turno: turnos[0], activo: true });
    } else {
      res.json({ success: true, turno: null, activo: false });
    }
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/turnos/abrir', async (req, res) => {
  try {
    const { empresa_id, sucursal_id, caja_id, usuario_id, saldo_inicial } = req.body;
    
    const [abiertos] = await db.query(
      'SELECT turno_id FROM turnos WHERE sucursal_id = ? AND estado = "ABIERTO"',
      [sucursal_id]
    );
    
    if (abiertos.length > 0) {
      return res.status(400).json({ success: false, error: 'Ya existe un turno abierto en esta sucursal' });
    }
    
    const id = generarID('TUR');
    
    await db.query(`
      INSERT INTO turnos (turno_id, empresa_id, sucursal_id, caja_id, usuario_id, fecha_apertura, saldo_inicial, estado)
      VALUES (?, ?, ?, ?, ?, NOW(), ?, 'ABIERTO')
    `, [id, empresa_id, sucursal_id, caja_id || null, usuario_id, saldo_inicial || 0]);
    
    res.json({ success: true, turno_id: id });
  } catch (e) {
    console.error('Error abrir turno:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// RESUMEN TURNO - CONSULTA PAGOS POR TURNO_ID
app.get('/api/turnos/resumen/:turnoID', async (req, res) => {
  try {
    const { turnoID } = req.params;
    
    const [turnos] = await db.query('SELECT * FROM turnos WHERE turno_id = ?', [turnoID]);
    if (turnos.length === 0) {
      return res.status(404).json({ success: false, error: 'Turno no encontrado' });
    }
    
    const turno = turnos[0];
    const saldoInicial = parseFloat(turno.saldo_inicial) || 0;
    
    // Ventas del turno
    const [ventasRes] = await db.query(`
      SELECT 
        COUNT(CASE WHEN estatus = 'PAGADA' THEN 1 END) as cantidad_ventas,
        COALESCE(SUM(CASE WHEN estatus = 'PAGADA' THEN total ELSE 0 END), 0) as total_ventas,
        COUNT(CASE WHEN estatus = 'CANCELADA' THEN 1 END) as cantidad_canceladas,
        COALESCE(SUM(CASE WHEN estatus = 'CANCELADA' THEN total ELSE 0 END), 0) as total_canceladas
      FROM ventas 
      WHERE turno_id = ?
    `, [turnoID]);
    
    // PAGOS POR MÉTODO - DIRECTO DE TABLA PAGOS CON TURNO_ID
    const [pagosPorMetodo] = await db.query(`
      SELECT 
        mp.metodo_pago_id,
        mp.nombre as metodo_nombre,
        COALESCE(mp.tipo, 'EFECTIVO') as tipo,
        COUNT(p.pago_id) as cantidad_pagos,
        COALESCE(SUM(p.monto), 0) as total
      FROM metodos_pago mp
      LEFT JOIN pagos p ON mp.metodo_pago_id = p.metodo_pago_id AND p.turno_id = ? AND p.estatus = 'APLICADO'
      WHERE mp.empresa_id = ? AND mp.activo = 'Y'
      GROUP BY mp.metodo_pago_id, mp.nombre, mp.tipo
      ORDER BY mp.orden, mp.nombre
    `, [turnoID, turno.empresa_id]);
    
    // Movimientos de caja
    const [movimientos] = await db.query(`
      SELECT tipo, COALESCE(SUM(monto), 0) as total, COUNT(*) as cantidad
      FROM movimientos_caja WHERE turno_id = ? GROUP BY tipo
    `, [turnoID]);
    
    let ingresos = 0, egresos = 0, cantIngresos = 0, cantEgresos = 0;
    movimientos.forEach(m => {
      if (m.tipo === 'INGRESO') {
        ingresos = parseFloat(m.total) || 0;
        cantIngresos = m.cantidad || 0;
      } else {
        egresos = parseFloat(m.total) || 0;
        cantEgresos = m.cantidad || 0;
      }
    });
    
    // Solo el efectivo cuenta para el arqueo
    let efectivoVentas = 0;
    const pagosMapeados = pagosPorMetodo.map(p => {
      const total = parseFloat(p.total) || 0;
      if ((p.tipo || '').toUpperCase() === 'EFECTIVO') {
        efectivoVentas += total;
      }
      return {
        metodo_pago_id: p.metodo_pago_id,
        nombre: p.metodo_nombre || 'Sin nombre',
        tipo: p.tipo || 'EFECTIVO',
        cantidad: parseInt(p.cantidad_pagos) || 0,
        total: total
      };
    });
    
    const efectivoEsperado = saldoInicial + efectivoVentas + ingresos - egresos;
    
    res.json({
      success: true,
      turno,
      ventas: {
        cantidad_ventas: parseInt(ventasRes[0].cantidad_ventas) || 0,
        total_ventas: parseFloat(ventasRes[0].total_ventas) || 0,
        cantidad_canceladas: parseInt(ventasRes[0].cantidad_canceladas) || 0,
        total_canceladas: parseFloat(ventasRes[0].total_canceladas) || 0
      },
      pagos_por_metodo: pagosMapeados,
      movimientos: {
        ingresos: ingresos,
        egresos: egresos,
        cant_ingresos: cantIngresos,
        cant_egresos: cantEgresos
      },
      efectivo_esperado: efectivoEsperado
    });
  } catch (e) {
    console.error('Error resumen turno:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// CERRAR TURNO - CONSULTA PAGOS POR TURNO_ID
app.post('/api/turnos/cerrar/:turnoID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { turnoID } = req.params;
    const { efectivo_declarado, observaciones, cerrado_por } = req.body;
    
    const [turnos] = await conn.query('SELECT * FROM turnos WHERE turno_id = ?', [turnoID]);
    if (turnos.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Turno no encontrado' });
    }
    
    const turno = turnos[0];
    const saldoInicial = parseFloat(turno.saldo_inicial) || 0;
    
    // Ventas del turno
    const [ventas] = await conn.query(`
      SELECT 
        COUNT(CASE WHEN estatus = 'PAGADA' THEN 1 END) as cantidad_ventas,
        COALESCE(SUM(CASE WHEN estatus = 'PAGADA' THEN total ELSE 0 END), 0) as total_ventas,
        COUNT(CASE WHEN estatus = 'CANCELADA' THEN 1 END) as cantidad_canceladas,
        COALESCE(SUM(CASE WHEN estatus = 'CANCELADA' THEN total ELSE 0 END), 0) as ventas_canceladas,
        COALESCE(SUM(CASE WHEN estatus = 'PAGADA' THEN (subtotal * COALESCE(descuento, 0) / 100) ELSE 0 END), 0) as descuentos_otorgados
      FROM ventas 
      WHERE turno_id = ?
    `, [turnoID]);
    
    // PAGOS POR TIPO - DIRECTO DE TABLA PAGOS CON TURNO_ID
    const [pagos] = await conn.query(`
      SELECT 
        COALESCE(mp.tipo, 'EFECTIVO') as tipo,
        COALESCE(SUM(p.monto), 0) as total
      FROM pagos p
      JOIN metodos_pago mp ON p.metodo_pago_id = mp.metodo_pago_id
      WHERE p.turno_id = ? AND p.estatus = 'APLICADO'
      GROUP BY mp.tipo
    `, [turnoID]);
    
    let ventasEfectivo = 0, ventasTarjeta = 0, ventasTransferencia = 0, ventasOtros = 0;
    pagos.forEach(p => {
      const tipo = (p.tipo || 'EFECTIVO').toUpperCase();
      const total = parseFloat(p.total) || 0;
      if (tipo === 'EFECTIVO') ventasEfectivo = total;
      else if (tipo === 'TARJETA' || tipo === 'TARJETA_DEBITO' || tipo === 'TARJETA_CREDITO') ventasTarjeta += total;
      else if (tipo === 'TRANSFERENCIA') ventasTransferencia = total;
      else ventasOtros += total;
    });
    
    // Ventas a crédito
    const [creditos] = await conn.query(`
      SELECT COALESCE(SUM(total), 0) as total
      FROM ventas 
      WHERE turno_id = ? AND tipo_venta = 'CREDITO' AND estatus = 'PAGADA'
    `, [turnoID]);
    const ventasCredito = parseFloat(creditos[0].total) || 0;
    
    // Movimientos de caja
    const [movimientos] = await conn.query(`
      SELECT tipo, COALESCE(SUM(monto), 0) as total
      FROM movimientos_caja WHERE turno_id = ? GROUP BY tipo
    `, [turnoID]);
    
    let ingresos = 0, egresos = 0;
    movimientos.forEach(m => {
      if (m.tipo === 'INGRESO') ingresos = parseFloat(m.total) || 0;
      else egresos = parseFloat(m.total) || 0;
    });
    
    const efectivoEsperado = saldoInicial + ventasEfectivo + ingresos - egresos;
    const efectivoDeclaradoNum = parseFloat(efectivo_declarado) || 0;
    const diferencia = efectivoDeclaradoNum - efectivoEsperado;
    const totalVentas = ventasEfectivo + ventasTarjeta + ventasTransferencia + ventasCredito + ventasOtros;
    
    await conn.query(`
      UPDATE turnos SET 
        fecha_cierre = NOW(),
        ventas_efectivo = ?,
        ventas_tarjeta = ?,
        ventas_transferencia = ?,
        ventas_credito = ?,
        ventas_otros = ?,
        total_ventas = ?,
        cantidad_ventas = ?,
        ventas_canceladas = ?,
        cantidad_canceladas = ?,
        descuentos_otorgados = ?,
        ingresos = ?,
        egresos = ?,
        efectivo_esperado = ?,
        efectivo_declarado = ?,
        diferencia = ?,
        observaciones = ?,
        cerrado_por = ?,
        estado = 'CERRADO'
      WHERE turno_id = ?
    `, [
      ventasEfectivo, ventasTarjeta, ventasTransferencia, ventasCredito, ventasOtros,
      totalVentas, ventas[0].cantidad_ventas || 0, 
      ventas[0].ventas_canceladas || 0, ventas[0].cantidad_canceladas || 0,
      ventas[0].descuentos_otorgados || 0,
      ingresos, egresos, efectivoEsperado, efectivoDeclaradoNum, diferencia,
      observaciones, cerrado_por, turnoID
    ]);
    
    await conn.commit();
    
    res.json({
      success: true,
      corte: {
        saldo_inicial: saldoInicial,
        ventas_efectivo: ventasEfectivo,
        ventas_tarjeta: ventasTarjeta,
        ventas_transferencia: ventasTransferencia,
        ventas_credito: ventasCredito,
        ventas_otros: ventasOtros,
        total_ventas: totalVentas,
        cantidad_ventas: ventas[0].cantidad_ventas || 0,
        cantidad_canceladas: ventas[0].cantidad_canceladas || 0,
        descuentos_otorgados: parseFloat(ventas[0].descuentos_otorgados) || 0,
        ingresos,
        egresos,
        efectivo_esperado: efectivoEsperado,
        efectivo_declarado: efectivoDeclaradoNum,
        diferencia
      }
    });
  } catch (e) {
    await conn.rollback();
    console.error('Error cerrar turno:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

app.post('/api/turnos/validar-admin', async (req, res) => {
  try {
    const { empresa_id, password } = req.body;
    
    const [admins] = await db.query(`
      SELECT usuario_id, nombre FROM usuarios 
      WHERE empresa_id = ? AND rol IN ('ADMIN', 'SUPERADMIN') AND contrasena = ? AND activo = 'Y'
      LIMIT 1
    `, [empresa_id, password]);
    
    if (admins.length > 0) {
      res.json({ success: true, admin: admins[0].nombre });
    } else {
      res.json({ success: false, error: 'Clave incorrecta' });
    }
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/turnos/reabrir/:turnoID', async (req, res) => {
  try {
    const { turnoID } = req.params;
    const { autorizado_por } = req.body;
    
    await db.query(`
      UPDATE turnos SET 
        estado = 'ABIERTO',
        fecha_cierre = NULL,
        efectivo_declarado = NULL,
        diferencia = NULL,
        observaciones = CONCAT(COALESCE(observaciones, ''), ' [REABIERTO por ', ?, ' el ', NOW(), ']')
      WHERE turno_id = ?
    `, [autorizado_por, turnoID]);
    
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== MOVIMIENTOS DE CAJA ====================

app.get('/api/movimientos-caja/:turnoID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT m.*, u.nombre as usuario_nombre
      FROM movimientos_caja m
      JOIN usuarios u ON m.usuario_id = u.usuario_id
      WHERE m.turno_id = ?
      ORDER BY m.fecha_hora DESC
    `, [req.params.turnoID]);
    res.json({ success: true, movimientos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/movimientos-caja', async (req, res) => {
  try {
    const { turno_id, empresa_id, sucursal_id, usuario_id, tipo, monto, concepto, referencia, notas } = req.body;
    
    const [turnos] = await db.query(
      'SELECT estado FROM turnos WHERE turno_id = ?',
      [turno_id]
    );
    
    if (turnos.length === 0 || turnos[0].estado !== 'ABIERTO') {
      return res.status(400).json({ success: false, error: 'El turno no está abierto' });
    }
    
    const id = generarID('MOV');
    await db.query(`
      INSERT INTO movimientos_caja (movimiento_id, turno_id, empresa_id, sucursal_id, usuario_id, tipo, monto, concepto, referencia, notas, fecha_hora)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `, [id, turno_id, empresa_id, sucursal_id, usuario_id, tipo, monto, concepto, referencia || null, notas || null]);
    
    res.json({ success: true, movimiento_id: id });
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

// Validar clave de administrador (para cualquier acción)
app.post('/api/auth/validar-admin', async (req, res) => {
    try {
        const { empresa_id, password } = req.body;
        
        if (!password) {
            return res.json({ success: false, error: 'Clave requerida' });
        }
        
        // Buscar usuarios admin de la empresa
        const [admins] = await db.query(`
            SELECT usuario_id, nombre, password 
            FROM usuarios 
            WHERE empresa_id = ? 
            AND rol IN ('ADMIN', 'SUPERADMIN', 'GERENTE') 
            AND activo = 'Y'
        `, [empresa_id]);
        
        // Verificar si algún admin tiene esa clave
        for (const admin of admins) {
            // Comparar contraseña (ajusta según tu método de hash)
            if (admin.password === password) {
                return res.json({ 
                    success: true, 
                    admin: admin.nombre,
                    usuario_id: admin.usuario_id
                });
            }
        }
        
        res.json({ success: false, error: 'Clave incorrecta' });
        
    } catch (error) {
        console.error('Error validando admin:', error);
        res.status(500).json({ success: false, error: 'Error del servidor' });
    }
});
