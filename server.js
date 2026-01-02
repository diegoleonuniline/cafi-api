require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({ origin: '*' }));
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
    const { email, password } = req.body;
    
    if (!email || !password) {
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
    `, [email.toLowerCase().trim()]);
    
    if (usuarios.length === 0) {
      return res.status(401).json({ success: false, error: 'Usuario no encontrado' });
    }
    
    const usuario = usuarios[0];
    
    if (usuario.contrasena !== password) {
      return res.status(401).json({ success: false, error: 'Contraseña incorrecta' });
    }
    
    if (usuario.empresa_activa !== 'Y') {
      return res.status(401).json({ success: false, error: 'Empresa inactiva' });
    }
    
    const token = jwt.sign({
      usuario_id: usuario.usuario_id,
      email: usuario.email,
      nombre: usuario.nombre,
      rol: usuario.rol,
      empresa_id: usuario.empresa_id,
      sucursal_id: usuario.sucursal_id,
      almacen_id: usuario.almacen_id
    }, process.env.JWT_SECRET, { expiresIn: '24h' });
    
    await db.query('UPDATE usuarios SET ultimo_acceso = NOW() WHERE usuario_id = ?', [usuario.usuario_id]);
    
    res.json({
      success: true,
      token,
      usuario: {
        id: usuario.usuario_id,
        email: usuario.email,
        nombre: usuario.nombre,
        rol: usuario.rol,
        empresa_id: usuario.empresa_id,
        empresa_nombre: usuario.empresa_nombre,
        sucursal_id: usuario.sucursal_id,
        sucursal_nombre: usuario.sucursal_nombre,
        almacen_id: usuario.almacen_id
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

// ==================== CATÁLOGOS ====================

// Categorías
app.get('/api/categorias/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM categorias WHERE empresa_id = ? AND activo = "Y" ORDER BY orden, nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, categorias: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/categorias', async (req, res) => {
  try {
    const { empresa_id, nombre, color, icono, orden } = req.body;
    const categoria_id = generarID('CAT');
    await db.query(
      'INSERT INTO categorias (categoria_id, empresa_id, nombre, color, icono, orden) VALUES (?, ?, ?, ?, ?, ?)',
      [categoria_id, empresa_id, nombre, color || '#3498db', icono, orden || 0]
    );
    res.json({ success: true, categoria_id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/categorias/:id', async (req, res) => {
  try {
    const { nombre, color, icono, orden, activo } = req.body;
    await db.query(
      'UPDATE categorias SET nombre=?, color=?, icono=?, orden=?, activo=? WHERE categoria_id=?',
      [nombre, color, icono, orden, activo, req.params.id]
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Productos
app.get('/api/productos/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT p.*, c.nombre as categoria_nombre 
      FROM productos p 
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      WHERE p.empresa_id = ? AND p.activo = "Y" 
      ORDER BY p.nombre
    `, [req.params.empresaID]);
    res.json({ success: true, productos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/productos', async (req, res) => {
  try {
    const d = req.body;
    const producto_id = generarID('PROD');
    await db.query(`
      INSERT INTO productos (producto_id, empresa_id, categoria_id, codigo_barras, codigo_interno,
        nombre, nombre_corto, nombre_pos, unidad_venta, unidad_compra_id, factor_compra,
        costo, precio1, precio2, precio3, precio4, permite_descuento, descuento_maximo, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [producto_id, d.empresa_id, d.categoria_id, d.codigo_barras, d.codigo_interno,
        d.nombre, d.nombre_corto, d.nombre_pos, d.unidad_venta || 'PZ', d.unidad_compra_id || 'PZ', 
        d.factor_compra || 1, d.costo || 0, d.precio1 || 0, d.precio2 || 0, d.precio3 || 0, 
        d.precio4 || 0, d.permite_descuento || 'Y', d.descuento_maximo || 0]);
    res.json({ success: true, producto_id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/productos/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE productos SET categoria_id=?, codigo_barras=?, codigo_interno=?, nombre=?, 
        nombre_corto=?, nombre_pos=?, unidad_venta=?, costo=?, precio1=?, precio2=?, 
        precio3=?, precio4=?, permite_descuento=?, descuento_maximo=?, activo=?
      WHERE producto_id=?
    `, [d.categoria_id, d.codigo_barras, d.codigo_interno, d.nombre, d.nombre_corto, 
        d.nombre_pos, d.unidad_venta, d.costo, d.precio1, d.precio2, d.precio3, d.precio4,
        d.permite_descuento, d.descuento_maximo, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
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

// Clientes
app.get('/api/clientes/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM clientes WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, clientes: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/clientes', async (req, res) => {
  try {
    const d = req.body;
    const cliente_id = generarID('CLI');
    await db.query(`
      INSERT INTO clientes (cliente_id, empresa_id, nombre, telefono, email, tipo_precio, 
        permite_credito, limite_credito) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [cliente_id, d.empresa_id, d.nombre, d.telefono, d.email, d.tipo_precio || 1, 
        d.permite_credito || 'N', d.limite_credito || 0]);
    res.json({ success: true, cliente_id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/clientes/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE clientes SET nombre=?, telefono=?, email=?, tipo_precio=?, 
        permite_credito=?, limite_credito=?, activo=? WHERE cliente_id=?
    `, [d.nombre, d.telefono, d.email, d.tipo_precio, d.permite_credito, 
        d.limite_credito, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Métodos de pago
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

// Cargar datos POS
app.get('/api/pos/cargar/:empresaID/:sucursalID', async (req, res) => {
  try {
    const { empresaID, sucursalID } = req.params;
    
    const [productos] = await db.query(`
      SELECT p.*, c.nombre as categoria_nombre, c.color as categoria_color,
             COALESCE(i.stock, 0) as stock
      FROM productos p
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      LEFT JOIN inventario i ON p.producto_id = i.producto_id 
        AND i.almacen_id = (SELECT almacen_id FROM almacenes WHERE sucursal_id = ? AND es_punto_venta = 'Y' LIMIT 1)
      WHERE p.empresa_id = ? AND p.activo = 'Y' AND p.es_vendible = 'Y'
      ORDER BY p.nombre
    `, [sucursalID, empresaID]);
    
    const [categorias] = await db.query(
      'SELECT * FROM categorias WHERE empresa_id = ? AND activo = "Y" ORDER BY orden',
      [empresaID]
    );
    
    const [clientes] = await db.query(
      'SELECT cliente_id, nombre, telefono, tipo_precio, permite_credito, limite_credito, saldo FROM clientes WHERE empresa_id = ? AND activo = "Y"',
      [empresaID]
    );
    
    const [metodos] = await db.query(
      'SELECT * FROM metodos_pago WHERE empresa_id = ? AND activo = "Y" ORDER BY orden',
      [empresaID]
    );
    
    res.json({ success: true, productos, categorias, clientes, metodos });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Health
app.get('/health', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (e) {
    res.json({ status: 'ok', db: 'error', error: e.message });
  }
});

app.listen(PORT, () => console.log(`CAFI API puerto ${PORT}`));

// ==================== VENTAS ====================

app.post('/api/ventas', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const d = req.body;
    const venta_id = generarID('VTA');
    
    // Insertar venta
    await conn.query(`
      INSERT INTO ventas (venta_id, empresa_id, sucursal_id, almacen_id, usuario_id, cliente_id, total, estatus)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'PAGADA')
    `, [venta_id, d.empresa_id, d.sucursal_id, d.almacen_id, d.usuario_id, d.cliente_id, d.total]);
    
    // Insertar detalles
    for (const item of d.items) {
      const detalle_id = generarID('DET');
      await conn.query(`
        INSERT INTO detalle_venta (detalle_id, venta_id, producto_id, cantidad, precio_unitario, subtotal)
        VALUES (?, ?, ?, ?, ?, ?)
      `, [detalle_id, venta_id, item.producto_id, item.cantidad, item.precio_unitario, item.subtotal]);
    }
    
    // Insertar pagos
    for (const pago of d.pagos) {
      const pago_id = generarID('PAG');
      await conn.query(`
        INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, metodo_pago_id, monto, usuario_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `, [pago_id, d.empresa_id, d.sucursal_id, venta_id, pago.metodo_pago_id, pago.monto, d.usuario_id]);
    }
    
    await conn.commit();
    res.json({ success: true, venta_id });
    
  } catch (e) {
    await conn.rollback();
    console.error('Error venta:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});
