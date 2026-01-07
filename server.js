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

app.post('/api/auth/validar-admin', async (req, res) => {
  try {
    const { empresa_id, password } = req.body;
    
    if (!password) {
      return res.json({ success: false, error: 'Clave requerida' });
    }
    
    const [admins] = await db.query(`
      SELECT usuario_id, nombre 
      FROM usuarios 
      WHERE empresa_id = ? 
        AND contrasena = ?
        AND rol IN ('SuperAdmin', 'Admin', 'Gerente', 'Supervisor')
        AND activo = 'Y'
      LIMIT 1
    `, [empresa_id, password]);
    
    if (admins.length > 0) {
      return res.json({ 
        success: true, 
        admin: admins[0].nombre,
        usuario_id: admins[0].usuario_id
      });
    }
    
    res.json({ success: false, error: 'Clave incorrecta' });
    
  } catch (e) {
    console.error('Error validando admin:', e);
    res.json({ success: false, error: 'Error del servidor' });
  }
});

// ==================== EMPRESAS ====================

app.get('/api/empresas/:id', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT * FROM empresas WHERE empresa_id = ?', [req.params.id]);
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'No encontrada' });
    res.json({ success: true, empresa: rows[0] });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/empresas/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE empresas SET 
        nombre=?, rfc=?, telefono=?, email=?, direccion=?, 
        regimen_fiscal=?, codigo_postal=?
      WHERE empresa_id=?
    `, [d.nombre, d.rfc, d.telefono, d.email, d.direccion, d.regimen_fiscal, d.codigo_postal, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== SUCURSALES ====================

app.get('/api/sucursales/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT *, activa as activo FROM sucursales WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, sucursales: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/sucursales', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('SUC');
    await db.query(`
      INSERT INTO sucursales (
        sucursal_id, empresa_id, codigo, nombre, tipo,
        direccion, colonia, ciudad, estado, codigo_postal,
        telefono, email, responsable,
        horario_apertura, horario_cierre, dias_operacion,
        permite_venta, permite_compra, permite_traspaso, activa
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id, d.empresa_id, d.codigo, d.nombre, d.tipo || 'TIENDA',
      d.direccion, d.colonia, d.ciudad, d.estado, d.codigo_postal,
      d.telefono, d.email, d.responsable,
      d.horario_apertura, d.horario_cierre, d.dias_operacion || 'L,M,X,J,V,S',
      d.permite_venta || 'Y', d.permite_compra || 'Y', d.permite_traspaso || 'Y', d.activo || 'Y'
    ]);
    res.json({ success: true, id, sucursal_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/sucursales/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE sucursales SET 
        codigo=?, nombre=?, tipo=?,
        direccion=?, colonia=?, ciudad=?, estado=?, codigo_postal=?,
        telefono=?, email=?, responsable=?,
        horario_apertura=?, horario_cierre=?, dias_operacion=?,
        permite_venta=?, permite_compra=?, permite_traspaso=?, activa=?
      WHERE sucursal_id=?
    `, [
      d.codigo, d.nombre, d.tipo,
      d.direccion, d.colonia, d.ciudad, d.estado, d.codigo_postal,
      d.telefono, d.email, d.responsable,
      d.horario_apertura, d.horario_cierre, d.dias_operacion,
      d.permite_venta, d.permite_compra, d.permite_traspaso, d.activo,
      req.params.id
    ]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/sucursales/:id', async (req, res) => {
  try {
    await db.query('UPDATE sucursales SET activa = "N" WHERE sucursal_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// ==================== USUARIOS ====================

app.get('/api/usuarios/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT u.*, s.nombre as sucursal_nombre 
      FROM usuarios u
      LEFT JOIN sucursales s ON u.sucursal_id = s.sucursal_id
      WHERE u.empresa_id = ? AND u.activo = 'Y'
      ORDER BY u.nombre
    `, [req.params.empresaID]);
    res.json({ success: true, usuarios: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/usuarios', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('USR');
    await db.query(`
      INSERT INTO usuarios (usuario_id, empresa_id, sucursal_id, email, contrasena, nombre, rol, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, d.empresa_id, d.sucursal_id, d.email, d.contrasena, d.nombre, d.rol, d.activo || 'Y']);
    res.json({ success: true, id, usuario_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/usuarios/:id', async (req, res) => {
  try {
    const d = req.body;
    if (d.contrasena) {
      await db.query(`
        UPDATE usuarios SET nombre=?, contrasena=?, rol=?, sucursal_id=?, activo=? 
        WHERE usuario_id=?
      `, [d.nombre, d.contrasena, d.rol, d.sucursal_id, d.activo, req.params.id]);
    } else {
      await db.query(`
        UPDATE usuarios SET nombre=?, rol=?, sucursal_id=?, activo=? 
        WHERE usuario_id=?
      `, [d.nombre, d.rol, d.sucursal_id, d.activo, req.params.id]);
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/usuarios/:id', async (req, res) => {
  try {
    await db.query('UPDATE usuarios SET activo = "N" WHERE usuario_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
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
      INSERT INTO impuestos (
        impuesto_id, empresa_id, nombre, tipo, valor,
        incluido_en_precio, aplica_ventas, aplica_compras, cuenta_contable, activo
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [
      id, d.empresa_id, d.nombre, d.tipo || 'PORCENTAJE', d.valor || 0,
      d.incluido_en_precio || 'Y', d.aplica_ventas || 'Y', d.aplica_compras || 'Y', d.cuenta_contable
    ]);
    res.json({ success: true, id, impuesto_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/impuestos/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE impuestos SET 
        nombre=?, tipo=?, valor=?,
        incluido_en_precio=?, aplica_ventas=?, aplica_compras=?, cuenta_contable=?, activo=?
      WHERE impuesto_id=?
    `, [
      d.nombre, d.tipo, d.valor,
      d.incluido_en_precio, d.aplica_ventas, d.aplica_compras, d.cuenta_contable, d.activo,
      req.params.id
    ]);
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
      'SELECT * FROM metodos_pago WHERE empresa_id = ? AND activo = "Y" ORDER BY orden, nombre',
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
      INSERT INTO metodos_pago (
        metodo_pago_id, empresa_id, nombre, tipo,
        requiere_referencia, permite_cambio, comision_porcentaje, comision_fija,
        cuenta_contable, orden, activo
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [
      id, d.empresa_id, d.nombre, d.tipo || 'EFECTIVO',
      d.requiere_referencia || 'N', d.permite_cambio || 'N', d.comision_porcentaje || 0, d.comision_fija || 0,
      d.cuenta_contable, d.orden || 0
    ]);
    res.json({ success: true, id, metodo_pago_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/metodos-pago/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE metodos_pago SET 
        nombre=?, tipo=?, requiere_referencia=?, permite_cambio=?,
        comision_porcentaje=?, comision_fija=?, cuenta_contable=?, orden=?, activo=?
      WHERE metodo_pago_id=?
    `, [
      d.nombre, d.tipo, d.requiere_referencia, d.permite_cambio,
      d.comision_porcentaje, d.comision_fija, d.cuenta_contable, d.orden, d.activo,
      req.params.id
    ]);
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

// ==================== UNIDADES DE MEDIDA ====================

app.get('/api/unidades/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM unidades_medida WHERE activo = "Y" ORDER BY nombre'
    );
    res.json({ success: true, unidades: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/unidades/:empresaID/todos', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM unidades_medida ORDER BY nombre'
    );
    res.json({ success: true, unidades: rows });
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

// ==================== CLIENTES ====================

app.get('/api/clientes/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM clientes WHERE empresa_id = ? AND activo = "Y" ORDER BY nombre',
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
    
    for (const item of d.items) {
      const detalleId = generarID('DET');
      const subtotalItem = item.precio_unitario * item.cantidad;
      const descuentoPct = item.descuento || 0;
      const descuentoMonto = subtotalItem * descuentoPct / 100;
      
      await conn.query(`
        INSERT INTO detalle_venta (
          detalle_id, venta_id, producto_id, descripcion, cantidad, unidad_id,
          precio_lista, precio_unitario, descuento_pct, descuento_monto, subtotal, estatus
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVO')
      `, [
        detalleId, ventaId, item.producto_id, item.descripcion, item.cantidad,
        item.unidad_id || 'PZ', item.precio_unitario, item.precio_unitario, 
        descuentoPct, descuentoMonto, item.subtotal
      ]);
    }
    
    if (d.pagos && d.pagos.length > 0) {
      for (const pago of d.pagos) {
        const pagoId = generarID('PAG');
        await conn.query(`
          INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, turno_id, metodo_pago_id, monto, usuario_id, estatus)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APLICADO')
        `, [pagoId, d.empresa_id, d.sucursal_id, ventaId, d.turno_id, pago.metodo_pago_id, pago.monto, d.usuario_id]);
      }
    }
    
    const historialId = generarID('HIST');
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, fecha)
      VALUES (?, ?, 'CREACION', ?, ?, NOW())
    `, [historialId, ventaId, 'Venta creada. Total: $' + d.total.toFixed(2), d.usuario_id]);
    
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

// VENTAS DEL TURNO
app.get('/api/ventas/turno/:turnoID', async (req, res) => {
  try {
    const { turnoID } = req.params;
    
    const [ventas] = await db.query(`
      SELECT v.*, 
             c.nombre as cliente_nombre,
             u.nombre as usuario_nombre,
             (SELECT COUNT(*) FROM detalle_venta dv WHERE dv.venta_id = v.venta_id AND dv.estatus = 'ACTIVO') as num_productos
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      LEFT JOIN usuarios u ON v.usuario_id = u.usuario_id
      WHERE v.turno_id = ?
      ORDER BY v.fecha_hora DESC
    `, [turnoID]);
    
    res.json({ success: true, ventas });
  } catch (e) {
    console.error('Error obteniendo ventas del turno:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// DETALLE COMPLETO DE VENTA
app.get('/api/ventas/detalle-completo/:ventaID', async (req, res) => {
  try {
    const { ventaID } = req.params;
    
    const [ventas] = await db.query(`
      SELECT v.*, 
             c.nombre as cliente_nombre,
             u.nombre as usuario_nombre
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      LEFT JOIN usuarios u ON v.usuario_id = u.usuario_id
      WHERE v.venta_id = ?
    `, [ventaID]);
    
    if (ventas.length === 0) {
      return res.status(404).json({ success: false, error: 'Venta no encontrada' });
    }
    
    const [productos] = await db.query(`
      SELECT d.*, 
             p.nombre as producto_nombre,
             p.codigo_barras,
             p.unidad_venta as unidad
      FROM detalle_venta d
      LEFT JOIN productos p ON d.producto_id = p.producto_id
      WHERE d.venta_id = ?
      ORDER BY d.detalle_id
    `, [ventaID]);
    
    const [pagos] = await db.query(`
      SELECT p.*,
             mp.nombre as metodo_nombre,
             mp.tipo
      FROM pagos p
      LEFT JOIN metodos_pago mp ON p.metodo_pago_id = mp.metodo_pago_id
      WHERE p.venta_id = ?
      ORDER BY p.fecha_hora DESC
    `, [ventaID]);
    
    const [historial] = await db.query(`
      SELECT h.*,
             u.nombre as usuario_nombre
      FROM venta_historial h
      LEFT JOIN usuarios u ON h.usuario_id = u.usuario_id
      WHERE h.venta_id = ?
      ORDER BY h.fecha DESC
    `, [ventaID]);
    
    res.json({
      success: true,
      venta: ventas[0],
      productos,
      pagos,
      historial
    });
  } catch (e) {
    console.error('Error obteniendo detalle:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// CANCELAR VENTA COMPLETA
app.post('/api/ventas/cancelar-completa/:ventaID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { ventaID } = req.params;
    const { motivo_cancelacion, cancelado_por, autorizado_por } = req.body;
    
    const [ventas] = await conn.query('SELECT * FROM ventas WHERE venta_id = ?', [ventaID]);
    if (ventas.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Venta no encontrada' });
    }
    
    const venta = ventas[0];
    const pagado = parseFloat(venta.pagado) || 0;
    
    await conn.query(`
      UPDATE ventas SET 
        estatus = 'CANCELADA',
        motivo_cancelacion = ?,
        cancelado_por = ?,
        fecha_cancelacion = NOW()
      WHERE venta_id = ?
    `, [motivo_cancelacion, cancelado_por, ventaID]);
    
    await conn.query(`
      UPDATE detalle_venta SET 
        estatus = 'CANCELADO',
        motivo_cancelacion = 'Venta cancelada',
        cancelado_por = ?,
        fecha_cancelacion = NOW()
      WHERE venta_id = ?
    `, [cancelado_por, ventaID]);
    
    await conn.query(`
      UPDATE pagos SET estatus = 'CANCELADO' WHERE venta_id = ?
    `, [ventaID]);
    
    const historialId = generarID('HIST');
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, datos_anteriores, fecha)
      VALUES (?, ?, 'CANCELACION', ?, ?, ?, NOW())
    `, [
      historialId, 
      ventaID, 
      'Venta cancelada. Motivo: ' + motivo_cancelacion + '. Autorizado: ' + autorizado_por + '. Devolución: $' + pagado.toFixed(2),
      cancelado_por,
      JSON.stringify({ total: venta.total, pagado: pagado, estatus_anterior: venta.estatus })
    ]);
    
    await conn.commit();
    
    res.json({ 
      success: true, 
      devolucion: pagado,
      message: 'Venta cancelada correctamente'
    });
  } catch (e) {
    await conn.rollback();
    console.error('Error cancelando venta:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

// CANCELAR PRODUCTO INDIVIDUAL
app.post('/api/ventas/cancelar-producto/:detalleID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { detalleID } = req.params;
    const { venta_id, cantidad_cancelar, motivo, cancelado_por, autorizado_por } = req.body;
    
    const [detalles] = await conn.query('SELECT * FROM detalle_venta WHERE detalle_id = ?', [detalleID]);
    if (detalles.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Producto no encontrado' });
    }
    
    const detalle = detalles[0];
    const precioUnit = parseFloat(detalle.precio_unitario) || 0;
    const cantidadActual = parseFloat(detalle.cantidad) || 0;
    const cantidadCancelar = Math.min(parseFloat(cantidad_cancelar), cantidadActual);
    const devolucion = cantidadCancelar * precioUnit;
    
    if (cantidadCancelar >= cantidadActual) {
      await conn.query(`
        UPDATE detalle_venta SET 
          estatus = 'CANCELADO',
          cantidad_cancelada = ?,
          motivo_cancelacion = ?,
          cancelado_por = ?,
          fecha_cancelacion = NOW()
        WHERE detalle_id = ?
      `, [cantidadCancelar, motivo, cancelado_por, detalleID]);
    } else {
      await conn.query(`
        UPDATE detalle_venta SET 
          cantidad = cantidad - ?,
          cantidad_cancelada = COALESCE(cantidad_cancelada, 0) + ?,
          subtotal = (cantidad - ?) * precio_unitario
        WHERE detalle_id = ?
      `, [cantidadCancelar, cantidadCancelar, cantidadCancelar, detalleID]);
    }
    
    const [nuevoTotalRes] = await conn.query(`
      SELECT COALESCE(SUM(subtotal), 0) as nuevo_total 
      FROM detalle_venta 
      WHERE venta_id = ? AND estatus = 'ACTIVO'
    `, [venta_id]);
    const nuevoTotal = parseFloat(nuevoTotalRes[0].nuevo_total) || 0;
    
    await conn.query('UPDATE ventas SET total = ? WHERE venta_id = ?', [nuevoTotal, venta_id]);
    
    const historialId = generarID('HIST');
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, datos_anteriores, fecha)
      VALUES (?, ?, 'PRODUCTO_CANCELADO', ?, ?, ?, NOW())
    `, [
      historialId,
      venta_id,
      'Producto cancelado: ' + (detalle.descripcion || 'Producto') + ' x' + cantidadCancelar + '. Motivo: ' + motivo + '. Autorizado: ' + autorizado_por + '. Devolución: $' + devolucion.toFixed(2),
      cancelado_por,
      JSON.stringify({ producto_id: detalle.producto_id, cantidad_cancelada: cantidadCancelar, precio: precioUnit })
    ]);
    
    await conn.commit();
    
    res.json({
      success: true,
      devolucion: devolucion,
      nuevo_total: nuevoTotal
    });
  } catch (e) {
    await conn.rollback();
    console.error('Error cancelando producto:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

// CAMBIAR MÉTODO DE PAGO
app.post('/api/ventas/cambiar-pago/:pagoID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { pagoID } = req.params;
    const { venta_id, nuevo_metodo_id, referencia, motivo, modificado_por, autorizado_por } = req.body;
    
    const [pagos] = await conn.query(`
      SELECT p.*, mp.nombre as metodo_nombre 
      FROM pagos p 
      LEFT JOIN metodos_pago mp ON p.metodo_pago_id = mp.metodo_pago_id
      WHERE p.pago_id = ?
    `, [pagoID]);
    
    if (pagos.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Pago no encontrado' });
    }
    
    const pagoAnterior = pagos[0];
    
    const [nuevoMetodo] = await conn.query('SELECT nombre FROM metodos_pago WHERE metodo_pago_id = ?', [nuevo_metodo_id]);
    const nuevoMetodoNombre = nuevoMetodo.length > 0 ? nuevoMetodo[0].nombre : 'Nuevo método';
    
    await conn.query(`
      UPDATE pagos SET 
        estatus = 'CANCELADO',
        motivo_cancelacion = ?
      WHERE pago_id = ?
    `, ['Cambio de método: ' + motivo, pagoID]);
    
    const nuevoPagoId = generarID('PAG');
    await conn.query(`
      INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, turno_id, metodo_pago_id, monto, referencia, usuario_id, reemplaza_pago_id, estatus, fecha_hora)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'APLICADO', NOW())
    `, [
      nuevoPagoId,
      pagoAnterior.empresa_id,
      pagoAnterior.sucursal_id,
      venta_id,
      pagoAnterior.turno_id,
      nuevo_metodo_id,
      pagoAnterior.monto,
      referencia || null,
      modificado_por,
      pagoID
    ]);
    
    const historialId = generarID('HIST');
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, datos_anteriores, fecha)
      VALUES (?, ?, 'CAMBIO_PAGO', ?, ?, ?, NOW())
    `, [
      historialId,
      venta_id,
      'Cambio método: ' + (pagoAnterior.metodo_nombre || 'Anterior') + ' → ' + nuevoMetodoNombre + '. Monto: $' + parseFloat(pagoAnterior.monto).toFixed(2) + '. Motivo: ' + motivo + '. Autorizado: ' + autorizado_por,
      modificado_por,
      JSON.stringify({ pago_anterior: pagoID, metodo_anterior: pagoAnterior.metodo_pago_id })
    ]);
    
    await conn.commit();
    
    res.json({ success: true, nuevo_pago_id: nuevoPagoId });
  } catch (e) {
    await conn.rollback();
    console.error('Error cambiando pago:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

// REABRIR VENTA
app.post('/api/ventas/reabrir/:ventaID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { ventaID } = req.params;
    const { usuario_id, autorizado_por } = req.body;
    
    await conn.query(`
      UPDATE ventas SET 
        reabierta = 'Y',
        fecha_reapertura = NOW()
      WHERE venta_id = ?
    `, [ventaID]);
    
    const historialId = generarID('HIST');
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, fecha)
      VALUES (?, ?, 'REAPERTURA', ?, ?, NOW())
    `, [
      historialId,
      ventaID,
      'Venta reabierta para agregar productos. Autorizado: ' + autorizado_por,
      usuario_id
    ]);
    
    await conn.commit();
    
    res.json({ success: true });
  } catch (e) {
    await conn.rollback();
    console.error('Error reabriendo venta:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

// COBRAR COMPLEMENTO
app.post('/api/ventas/cobrar-complemento/:ventaID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { ventaID } = req.params;
    const { monto_cobrado, metodo_pago_id, cambio, productos_nuevos, nuevo_total, usuario_id, turno_id } = req.body;
    
    const [ventas] = await conn.query('SELECT * FROM ventas WHERE venta_id = ?', [ventaID]);
    if (ventas.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Venta no encontrada' });
    }
    
    const venta = ventas[0];
    const pagadoAnterior = parseFloat(venta.pagado) || 0;
    
    if (productos_nuevos && productos_nuevos.length > 0) {
      for (const item of productos_nuevos) {
        const detalleId = generarID('DET');
        await conn.query(`
          INSERT INTO detalle_venta (
            detalle_id, venta_id, producto_id, descripcion, cantidad, unidad_id,
            precio_lista, precio_unitario, descuento_pct, subtotal, estatus, es_agregado_reapertura
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVO', 'Y')
        `, [
          detalleId, ventaID, item.producto_id, item.descripcion, item.cantidad,
          item.unidad_id || 'PZ', item.precio_unitario, item.precio_unitario, 
          item.descuento || 0, item.subtotal
        ]);
      }
    }
    
    const pagoId = generarID('PAG');
    await conn.query(`
      INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, turno_id, metodo_pago_id, monto, usuario_id, estatus, es_complemento)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APLICADO', 'Y')
    `, [pagoId, venta.empresa_id, venta.sucursal_id, ventaID, turno_id, metodo_pago_id, monto_cobrado, usuario_id]);
    
    await conn.query(`
      UPDATE ventas SET 
        total = ?,
        pagado = pagado + ?,
        cambio = COALESCE(cambio, 0) + ?,
        estatus = 'PAGADA',
        reabierta = 'Y'
      WHERE venta_id = ?
    `, [nuevo_total, monto_cobrado, cambio || 0, ventaID]);
    
    const historialId = generarID('HIST');
    const numNuevos = productos_nuevos ? productos_nuevos.length : 0;
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, fecha)
      VALUES (?, ?, 'COMPLEMENTO_PAGO', ?, ?, NOW())
    `, [
      historialId,
      ventaID,
      'Pago complementario: $' + monto_cobrado.toFixed(2) + '. ' + (numNuevos > 0 ? numNuevos + ' productos agregados. ' : '') + 'Nuevo total: $' + nuevo_total.toFixed(2),
      usuario_id
    ]);
    
    await conn.commit();
    
    res.json({
      success: true,
      folio: venta.folio,
      nuevo_total: nuevo_total,
      total_pagado: pagadoAnterior + monto_cobrado
    });
  } catch (e) {
    await conn.rollback();
    console.error('Error cobrando complemento:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
  }
});

// GUARDAR VENTA REABIERTA
app.post('/api/ventas/guardar-reabierta/:ventaID', async (req, res) => {
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    
    const { ventaID } = req.params;
    const { 
      productos_nuevos, 
      productos_modificados, 
      productos_eliminados,
      nuevo_total,
      devolucion,
      pago_nuevo,
      usuario_id,
      turno_id
    } = req.body;
    
    const [ventas] = await conn.query('SELECT * FROM ventas WHERE venta_id = ?', [ventaID]);
    if (ventas.length === 0) {
      await conn.rollback();
      return res.status(404).json({ success: false, error: 'Venta no encontrada' });
    }
    
    const venta = ventas[0];
    const pagadoAnterior = parseFloat(venta.pagado) || 0;
    
    if (productos_nuevos && productos_nuevos.length > 0) {
      for (const item of productos_nuevos) {
        const detalleId = generarID('DET');
        await conn.query(`
          INSERT INTO detalle_venta (
            detalle_id, venta_id, producto_id, descripcion, cantidad, unidad_id,
            precio_lista, precio_unitario, descuento_pct, subtotal, estatus, es_agregado_reapertura
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVO', 'Y')
        `, [
          detalleId, ventaID, item.producto_id, item.descripcion, item.cantidad,
          item.unidad_id || 'PZ', item.precio_unitario, item.precio_unitario, 
          item.descuento || 0, item.subtotal
        ]);
      }
    }
    
    if (productos_modificados && productos_modificados.length > 0) {
      for (const mod of productos_modificados) {
        await conn.query(`
          UPDATE detalle_venta SET 
            cantidad = ?,
            precio_unitario = ?,
            subtotal = ? * ?
          WHERE detalle_id = ?
        `, [mod.cantidad_nueva, mod.precio_nuevo, mod.cantidad_nueva, mod.precio_nuevo, mod.detalle_id]);
      }
    }
    
    if (productos_eliminados && productos_eliminados.length > 0) {
      for (const elim of productos_eliminados) {
        await conn.query(`
          UPDATE detalle_venta SET 
            estatus = 'CANCELADO',
            motivo_cancelacion = 'Eliminado en reapertura',
            cancelado_por = ?,
            fecha_cancelacion = NOW()
          WHERE detalle_id = ?
        `, [usuario_id, elim.detalle_id]);
      }
    }
    
    if (devolucion && devolucion.monto > 0) {
      const devId = generarID('DEV');
      await conn.query(`
        INSERT INTO devoluciones (
          devolucion_id, empresa_id, sucursal_id, venta_id, turno_id,
          monto, metodo_devolucion, tipo_metodo, referencia, notas,
          usuario_id, fecha_hora
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `, [
        devId, venta.empresa_id, venta.sucursal_id, ventaID, turno_id,
        devolucion.monto, devolucion.metodo_pago_id || 'EFECTIVO', devolucion.tipo,
        devolucion.referencia || null, devolucion.notas || null, usuario_id
      ]);
      
      await conn.query(`
        UPDATE ventas SET pagado = pagado - ? WHERE venta_id = ?
      `, [devolucion.monto, ventaID]);
    }
    
    if (pago_nuevo && pago_nuevo.monto > 0) {
      const pagoId = generarID('PAG');
      await conn.query(`
        INSERT INTO pagos (pago_id, empresa_id, sucursal_id, venta_id, turno_id, metodo_pago_id, monto, usuario_id, estatus, es_complemento)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'APLICADO', 'Y')
      `, [pagoId, venta.empresa_id, venta.sucursal_id, ventaID, turno_id, pago_nuevo.metodo_pago_id, pago_nuevo.monto, usuario_id]);
      
      await conn.query(`
        UPDATE ventas SET 
          pagado = pagado + ?,
          cambio = COALESCE(cambio, 0) + ?
        WHERE venta_id = ?
      `, [pago_nuevo.monto, pago_nuevo.cambio || 0, ventaID]);
    }
    
    await conn.query(`
      UPDATE ventas SET 
        total = ?,
        reabierta = 'Y',
        estatus = 'PAGADA'
      WHERE venta_id = ?
    `, [nuevo_total, ventaID]);
    
    const historialId = generarID('HIST');
    let descripcion = 'Venta reabierta modificada. Nuevo total: $' + nuevo_total.toFixed(2);
    if (devolucion && devolucion.monto > 0) {
      descripcion += '. Devolución: $' + devolucion.monto.toFixed(2) + ' en ' + devolucion.tipo;
    }
    if (pago_nuevo && pago_nuevo.monto > 0) {
      descripcion += '. Cobro adicional: $' + pago_nuevo.monto.toFixed(2);
    }
    
    await conn.query(`
      INSERT INTO venta_historial (historial_id, venta_id, tipo_accion, descripcion, usuario_id, fecha)
      VALUES (?, ?, 'MODIFICACION_REAPERTURA', ?, ?, NOW())
    `, [historialId, ventaID, descripcion, usuario_id]);
    
    await conn.commit();
    
    res.json({
      success: true,
      folio: venta.folio,
      nuevo_total: nuevo_total
    });
  } catch (e) {
    await conn.rollback();
    console.error('Error guardando venta reabierta:', e);
    res.status(500).json({ success: false, error: e.message });
  } finally {
    conn.release();
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

app.get('/api/turnos/resumen/:turnoID', async (req, res) => {
  try {
    const { turnoID } = req.params;
    
    const [turnos] = await db.query('SELECT * FROM turnos WHERE turno_id = ?', [turnoID]);
    if (turnos.length === 0) {
      return res.status(404).json({ success: false, error: 'Turno no encontrado' });
    }
    
    const turno = turnos[0];
    const saldoInicial = parseFloat(turno.saldo_inicial) || 0;
    
    const [ventasRes] = await db.query(`
      SELECT 
        COUNT(CASE WHEN estatus = 'PAGADA' THEN 1 END) as cantidad_ventas,
        COALESCE(SUM(CASE WHEN estatus = 'PAGADA' THEN total ELSE 0 END), 0) as total_ventas,
        COUNT(CASE WHEN estatus = 'CANCELADA' THEN 1 END) as cantidad_canceladas,
        COALESCE(SUM(CASE WHEN estatus = 'CANCELADA' THEN total ELSE 0 END), 0) as total_canceladas
      FROM ventas 
      WHERE turno_id = ?
    `, [turnoID]);
    
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
    
    const [creditos] = await conn.query(`
      SELECT COALESCE(SUM(total), 0) as total
      FROM ventas 
      WHERE turno_id = ? AND tipo_venta = 'CREDITO' AND estatus = 'PAGADA'
    `, [turnoID]);
    const ventasCredito = parseFloat(creditos[0].total) || 0;
    
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

// ==================== REPORTES ====================

app.get('/api/reportes/ventas-periodo', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, agrupar } = req.query;
    
    let groupBy, selectPeriodo;
    switch(agrupar) {
      case 'semana':
        groupBy = 'YEARWEEK(fecha_hora)';
        selectPeriodo = "CONCAT('Semana ', WEEK(fecha_hora), ' - ', YEAR(fecha_hora))";
        break;
      case 'mes':
        groupBy = "DATE_FORMAT(fecha_hora, '%Y-%m')";
        selectPeriodo = "DATE_FORMAT(fecha_hora, '%M %Y')";
        break;
      default:
        groupBy = 'DATE(fecha_hora)';
        selectPeriodo = "DATE_FORMAT(fecha_hora, '%d/%m/%Y')";
    }
    
    const [rows] = await db.query(`
      SELECT 
        ${selectPeriodo} as periodo,
        COUNT(*) as ventas,
        COALESCE(SUM(subtotal), 0) as subtotal,
        COALESCE(SUM(total - subtotal), 0) as impuestos,
        COALESCE(SUM(total), 0) as total,
        0 as productos
      FROM ventas
      WHERE empresa_id = ? 
        AND DATE(fecha_hora) >= ? 
        AND DATE(fecha_hora) <= ?
        AND estatus = 'PAGADA'
      GROUP BY ${groupBy}
      ORDER BY MIN(fecha_hora)
    `, [empresa_id, desde, hasta]);
    
    res.json({ success: true, datos: rows });
  } catch (e) {
    console.error('Error ventas-periodo:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/ventas-usuario', async (req, res) => {
  try {
    const { empresa_id, desde, hasta } = req.query;
    
    const [rows] = await db.query(`
      SELECT 
        u.nombre as usuario,
        COUNT(v.venta_id) as ventas,
        COALESCE(SUM(v.total), 0) as total,
        COALESCE(AVG(v.total), 0) as promedio,
        0 as productos
      FROM usuarios u
      LEFT JOIN ventas v ON u.usuario_id = v.usuario_id 
        AND DATE(v.fecha_hora) >= ? 
        AND DATE(v.fecha_hora) <= ?
        AND v.estatus = 'PAGADA'
      WHERE u.empresa_id = ? AND u.activo = 'Y'
      GROUP BY u.usuario_id, u.nombre
      HAVING ventas > 0
      ORDER BY total DESC
    `, [desde, hasta, empresa_id]);
    
    res.json({ success: true, datos: rows });
  } catch (e) {
    console.error('Error ventas-usuario:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/productos-vendidos', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, categoria_id, orden } = req.query;
    
    let query = `
      SELECT 
        p.codigo_barras as codigo,
        p.nombre as producto,
        COALESCE(c.nombre, 'Sin categoría') as categoria,
        COALESCE(SUM(dv.cantidad), 0) as cantidad,
        COALESCE(SUM(dv.subtotal), 0) as total,
        COALESCE(SUM(dv.cantidad * p.costo), 0) as costo
      FROM productos p
      LEFT JOIN detalle_venta dv ON p.producto_id = dv.producto_id AND dv.estatus = 'ACTIVO'
      LEFT JOIN ventas v ON dv.venta_id = v.venta_id 
        AND DATE(v.fecha_hora) >= ? 
        AND DATE(v.fecha_hora) <= ?
        AND v.estatus = 'PAGADA'
      LEFT JOIN categorias c ON p.categoria_id = c.categoria_id
      WHERE p.empresa_id = ?
    `;
    
    const params = [desde, hasta, empresa_id];
    
    if (categoria_id) {
      query += ' AND p.categoria_id = ?';
      params.push(categoria_id);
    }
    
    query += ' GROUP BY p.producto_id, p.codigo_barras, p.nombre, c.nombre HAVING cantidad > 0';
    query += orden === 'monto' ? ' ORDER BY total DESC' : ' ORDER BY cantidad DESC';
    query += ' LIMIT 100';
    
    const [rows] = await db.query(query, params);
    res.json({ success: true, datos: rows });
  } catch (e) {
    console.error('Error productos-vendidos:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/cortes', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, usuario_id } = req.query;
    
    let query = `
      SELECT 
        t.turno_id as corte_id,
        t.turno_id as folio,
        t.fecha_cierre,
        u.nombre as usuario_nombre,
        t.turno_id as turno_folio,
        COALESCE(t.efectivo_esperado, 0) as total_esperado,
        COALESCE(t.efectivo_declarado, 0) as total_declarado,
        t.observaciones
      FROM turnos t
      JOIN usuarios u ON t.usuario_id = u.usuario_id
      WHERE t.empresa_id = ? 
        AND t.estado = 'CERRADO'
        AND DATE(t.fecha_cierre) >= ? 
        AND DATE(t.fecha_cierre) <= ?
    `;
    
    const params = [empresa_id, desde, hasta];
    
    if (usuario_id) {
      query += ' AND t.usuario_id = ?';
      params.push(usuario_id);
    }
    
    query += ' ORDER BY t.fecha_cierre DESC';
    
    const [rows] = await db.query(query, params);
    res.json({ success: true, cortes: rows });
  } catch (e) {
    console.error('Error cortes:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/pagos', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, metodo_id, estado } = req.query;
    
    let query = `
      SELECT 
        p.pago_id,
        p.pago_id as folio,
        p.fecha_hora as fecha,
        v.folio as venta_folio,
        c.nombre as cliente_nombre,
        mp.nombre as metodo_nombre,
        p.monto,
        p.referencia,
        p.estatus as estado,
        u.nombre as usuario_nombre
      FROM pagos p
      LEFT JOIN ventas v ON p.venta_id = v.venta_id
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      JOIN metodos_pago mp ON p.metodo_pago_id = mp.metodo_pago_id
      JOIN usuarios u ON p.usuario_id = u.usuario_id
      WHERE p.empresa_id = ?
        AND DATE(p.fecha_hora) >= ?
        AND DATE(p.fecha_hora) <= ?
    `;
    
    const params = [empresa_id, desde, hasta];
    
    if (metodo_id) {
      query += ' AND p.metodo_pago_id = ?';
      params.push(metodo_id);
    }
    
    if (estado) {
      query += ' AND p.estatus = ?';
      params.push(estado);
    }
    
    query += ' ORDER BY p.fecha_hora DESC LIMIT 500';
    
    const [rows] = await db.query(query, params);
    res.json({ success: true, pagos: rows });
  } catch (e) {
    console.error('Error pagos:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/movimientos', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, tipo } = req.query;
    
    let query = `
      SELECT 
        m.fecha_hora as fecha,
        m.tipo,
        m.concepto,
        m.monto,
        u.nombre as usuario_nombre,
        t.turno_id as turno_folio,
        m.notas as observaciones
      FROM movimientos_caja m
      JOIN usuarios u ON m.usuario_id = u.usuario_id
      LEFT JOIN turnos t ON m.turno_id = t.turno_id
      WHERE m.empresa_id = ?
        AND DATE(m.fecha_hora) >= ?
        AND DATE(m.fecha_hora) <= ?
    `;
    
    const params = [empresa_id, desde, hasta];
    
    if (tipo) {
      query += ' AND m.tipo = ?';
      params.push(tipo);
    }
    
    query += ' ORDER BY m.fecha_hora DESC';
    
    const [rows] = await db.query(query, params);
    res.json({ success: true, movimientos: rows });
  } catch (e) {
    console.error('Error movimientos:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

app.get('/api/reportes/devoluciones', async (req, res) => {
  try {
    res.json({ success: true, devoluciones: [] });
  } catch (e) {
    console.error('Error devoluciones:', e);
    res.json({ success: true, devoluciones: [] });
  }
});

app.get('/api/reportes/cancelaciones', async (req, res) => {
  try {
    const { empresa_id, desde, hasta } = req.query;
    
    const [rows] = await db.query(`
      SELECT 
        v.folio,
        v.fecha_hora as fecha_venta,
        v.fecha_cancelacion,
        c.nombre as cliente_nombre,
        v.total,
        v.motivo_cancelacion as motivo,
        u.nombre as autorizo
      FROM ventas v
      LEFT JOIN clientes c ON v.cliente_id = c.cliente_id
      LEFT JOIN usuarios u ON v.cancelado_por = u.usuario_id
      WHERE v.empresa_id = ?
        AND v.estatus = 'CANCELADA'
        AND DATE(COALESCE(v.fecha_cancelacion, v.fecha_hora)) >= ?
        AND DATE(COALESCE(v.fecha_cancelacion, v.fecha_hora)) <= ?
      ORDER BY v.fecha_cancelacion DESC
    `, [empresa_id, desde, hasta]);
    
    res.json({ success: true, cancelaciones: rows });
  } catch (e) {
    console.error('Error cancelaciones:', e);
    res.json({ success: true, cancelaciones: [] });
  }
});

app.get('/api/reportes/clientes-frecuentes', async (req, res) => {
  try {
    const { empresa_id, desde, hasta, top } = req.query;
    const limite = parseInt(top) || 10;
    
    const [rows] = await db.query(`
      SELECT 
        c.nombre,
        c.telefono,
        COUNT(v.venta_id) as compras,
        COALESCE(SUM(v.total), 0) as total,
        COALESCE(AVG(v.total), 0) as promedio,
        MAX(v.fecha_hora) as ultima_compra
      FROM clientes c
      JOIN ventas v ON c.cliente_id = v.cliente_id
        AND DATE(v.fecha_hora) >= ?
        AND DATE(v.fecha_hora) <= ?
        AND v.estatus = 'PAGADA'
      WHERE c.empresa_id = ?
      GROUP BY c.cliente_id, c.nombre, c.telefono
      ORDER BY compras DESC, total DESC
      LIMIT ?
    `, [desde, hasta, empresa_id, limite]);
    
    res.json({ success: true, clientes: rows });
  } catch (e) {
    console.error('Error clientes-frecuentes:', e);
    res.json({ success: true, clientes: [] });
  }
});

app.get('/api/reportes/cuentas-cobrar', async (req, res) => {
  try {
    const { empresa_id, cliente_id } = req.query;
    
    let query = `
      SELECT 
        v.folio,
        v.fecha_hora as fecha,
        c.nombre as cliente_nombre,
        v.total,
        COALESCE(v.pagado, 0) as pagado,
        DATE_ADD(DATE(v.fecha_hora), INTERVAL 30 DAY) as vencimiento
      FROM ventas v
      JOIN clientes c ON v.cliente_id = c.cliente_id
      WHERE v.empresa_id = ?
        AND v.tipo_venta = 'CREDITO'
        AND v.estatus = 'PAGADA'
        AND v.total > COALESCE(v.pagado, 0)
    `;
    
    const params = [empresa_id];
    
    if (cliente_id) {
      query += ' AND v.cliente_id = ?';
      params.push(cliente_id);
    }
    
    query += ' ORDER BY v.fecha_hora DESC';
    
    const [rows] = await db.query(query, params);
    res.json({ success: true, cuentas: rows });
  } catch (e) {
    console.error('Error cuentas-cobrar:', e);
    res.json({ success: true, cuentas: [] });
  }
});

// DETALLE DE CORTE (para modal)
app.get('/api/cortes/:id', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT t.*, u.nombre as usuario_nombre
      FROM turnos t
      JOIN usuarios u ON t.usuario_id = u.usuario_id
      WHERE t.turno_id = ?
    `, [req.params.id]);
    
    if (rows.length === 0) return res.status(404).json({ success: false, error: 'No encontrado' });
    res.json({ success: true, corte: rows[0] });
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

// ==================== CATEGORÍAS ====================

app.get('/api/categorias/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM categorias WHERE empresa_id = ? ORDER BY orden, nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, categorias: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/categorias', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('CAT');
    await db.query(`
      INSERT INTO categorias (categoria_id, empresa_id, padre_id, codigo, nombre, descripcion, color, icono, orden, mostrar_pos, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.padre_id || null, d.codigo, d.nombre, d.descripcion, d.color || '#3498db', d.icono, d.orden || 0, d.mostrar_pos || 'Y']);
    res.json({ success: true, id, categoria_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/categorias/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE categorias SET padre_id=?, codigo=?, nombre=?, descripcion=?, color=?, icono=?, orden=?, mostrar_pos=?, activo=?
      WHERE categoria_id=?
    `, [d.padre_id || null, d.codigo, d.nombre, d.descripcion, d.color, d.icono, d.orden, d.mostrar_pos, d.activo, req.params.id]);
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

// ==================== SUBCATEGORÍAS ====================

app.get('/api/subcategorias/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT s.*, c.nombre as categoria_nombre 
      FROM subcategorias s
      LEFT JOIN categorias c ON s.categoria_id = c.categoria_id
      WHERE s.empresa_id = ? ORDER BY s.orden, s.nombre
    `, [req.params.empresaID]);
    res.json({ success: true, subcategorias: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/subcategorias', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('SCAT');
    await db.query(`
      INSERT INTO subcategorias (subcategoria_id, empresa_id, categoria_id, codigo, nombre, orden, activo)
      VALUES (?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.categoria_id, d.codigo, d.nombre, d.orden || 0]);
    res.json({ success: true, id, subcategoria_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/subcategorias/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE subcategorias SET categoria_id=?, codigo=?, nombre=?, orden=?, activo=?
      WHERE subcategoria_id=?
    `, [d.categoria_id, d.codigo, d.nombre, d.orden, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/subcategorias/:id', async (req, res) => {
  try {
    await db.query('UPDATE subcategorias SET activo = "N" WHERE subcategoria_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== MARCAS ====================

app.get('/api/marcas/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM marcas WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, marcas: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/marcas', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('MRC');
    await db.query(`
      INSERT INTO marcas (marca_id, empresa_id, nombre, logo_url, activo)
      VALUES (?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.nombre, d.logo_url]);
    res.json({ success: true, id, marca_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/marcas/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE marcas SET nombre=?, logo_url=?, activo=? WHERE marca_id=?
    `, [d.nombre, d.logo_url, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/marcas/:id', async (req, res) => {
  try {
    await db.query('UPDATE marcas SET activo = "N" WHERE marca_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== GRUPOS CLIENTE ====================

app.get('/api/grupos-cliente/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM grupos_cliente WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, grupos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/grupos-cliente', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('GRP');
    await db.query(`
      INSERT INTO grupos_cliente (grupo_id, empresa_id, nombre, tipo_precio, descuento_general, activo)
      VALUES (?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.nombre, d.tipo_precio || 1, d.descuento_general || 0]);
    res.json({ success: true, id, grupo_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/grupos-cliente/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE grupos_cliente SET nombre=?, tipo_precio=?, descuento_general=?, activo=? WHERE grupo_id=?
    `, [d.nombre, d.tipo_precio, d.descuento_general, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/grupos-cliente/:id', async (req, res) => {
  try {
    await db.query('UPDATE grupos_cliente SET activo = "N" WHERE grupo_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== PROVEEDORES ====================

app.get('/api/proveedores/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM proveedores WHERE empresa_id = ? ORDER BY nombre_comercial',
      [req.params.empresaID]
    );
    res.json({ success: true, proveedores: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/proveedores', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('PROV');
    await db.query(`
      INSERT INTO proveedores (
        proveedor_id, empresa_id, codigo, tipo_persona, razon_social, nombre_comercial, rfc,
        estado, ciudad, direccion, codigo_postal, telefono, celular, email,
        contacto_nombre, contacto_telefono, contacto_email,
        banco, cuenta_banco, clabe, dias_credito, limite_credito, notas, activo
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [
      id, d.empresa_id, d.codigo, d.tipo_persona || 'MORAL', d.razon_social, d.nombre_comercial, d.rfc,
      d.estado, d.ciudad, d.direccion, d.codigo_postal, d.telefono, d.celular, d.email,
      d.contacto_nombre, d.contacto_telefono, d.contacto_email,
      d.banco, d.cuenta_banco, d.clabe, d.dias_credito || 0, d.limite_credito || 0, d.notas
    ]);
    res.json({ success: true, id, proveedor_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/proveedores/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE proveedores SET 
        codigo=?, tipo_persona=?, razon_social=?, nombre_comercial=?, rfc=?,
        estado=?, ciudad=?, direccion=?, codigo_postal=?, telefono=?, celular=?, email=?,
        contacto_nombre=?, contacto_telefono=?, contacto_email=?,
        banco=?, cuenta_banco=?, clabe=?, dias_credito=?, limite_credito=?, notas=?, activo=?
      WHERE proveedor_id=?
    `, [
      d.codigo, d.tipo_persona, d.razon_social, d.nombre_comercial, d.rfc,
      d.estado, d.ciudad, d.direccion, d.codigo_postal, d.telefono, d.celular, d.email,
      d.contacto_nombre, d.contacto_telefono, d.contacto_email,
      d.banco, d.cuenta_banco, d.clabe, d.dias_credito, d.limite_credito, d.notas, d.activo,
      req.params.id
    ]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/proveedores/:id', async (req, res) => {
  try {
    await db.query('UPDATE proveedores SET activo = "N" WHERE proveedor_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== CUENTAS BANCARIAS ====================

app.get('/api/cuentas-bancarias/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM cuentas_bancarias WHERE empresa_id = ? ORDER BY banco',
      [req.params.empresaID]
    );
    res.json({ success: true, cuentas: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/cuentas-bancarias', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('CTA');
    await db.query(`
      INSERT INTO cuentas_bancarias (cuenta_id, empresa_id, banco, numero_cuenta, clabe, moneda_id, saldo, activa)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.banco, d.numero_cuenta, d.clabe, d.moneda_id || 'MXN', d.saldo || 0]);
    res.json({ success: true, id, cuenta_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/cuentas-bancarias/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE cuentas_bancarias SET banco=?, numero_cuenta=?, clabe=?, moneda_id=?, saldo=?, activa=? WHERE cuenta_id=?
    `, [d.banco, d.numero_cuenta, d.clabe, d.moneda_id, d.saldo, d.activa, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/cuentas-bancarias/:id', async (req, res) => {
  try {
    await db.query('UPDATE cuentas_bancarias SET activa = "N" WHERE cuenta_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== CATEGORÍAS GASTO ====================

app.get('/api/categorias-gasto/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(
      'SELECT * FROM categorias_gasto WHERE empresa_id = ? ORDER BY nombre',
      [req.params.empresaID]
    );
    res.json({ success: true, categorias: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/categorias-gasto', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('CATG');
    await db.query(`
      INSERT INTO categorias_gasto (categoria_gasto_id, empresa_id, codigo, nombre, tipo, cuenta_contable, activo)
      VALUES (?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.codigo, d.nombre, d.tipo || 'OPERATIVO', d.cuenta_contable]);
    res.json({ success: true, id, categoria_gasto_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/categorias-gasto/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE categorias_gasto SET codigo=?, nombre=?, tipo=?, cuenta_contable=?, activo=? WHERE categoria_gasto_id=?
    `, [d.codigo, d.nombre, d.tipo, d.cuenta_contable, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/categorias-gasto/:id', async (req, res) => {
  try {
    await db.query('UPDATE categorias_gasto SET activo = "N" WHERE categoria_gasto_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ==================== CONCEPTOS GASTO ====================

app.get('/api/conceptos-gasto/:empresaID', async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT c.*, cg.nombre as categoria_nombre 
      FROM conceptos_gasto c
      LEFT JOIN categorias_gasto cg ON c.categoria_gasto_id = cg.categoria_gasto_id
      WHERE c.empresa_id = ? ORDER BY c.nombre
    `, [req.params.empresaID]);
    res.json({ success: true, conceptos: rows });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.post('/api/conceptos-gasto', async (req, res) => {
  try {
    const d = req.body;
    const id = generarID('CONG');
    await db.query(`
      INSERT INTO conceptos_gasto (concepto_gasto_id, empresa_id, categoria_gasto_id, codigo, nombre, descripcion, requiere_factura, activo)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'Y')
    `, [id, d.empresa_id, d.categoria_gasto_id, d.codigo, d.nombre, d.descripcion, d.requiere_factura || 'N']);
    res.json({ success: true, id, concepto_gasto_id: id });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.put('/api/conceptos-gasto/:id', async (req, res) => {
  try {
    const d = req.body;
    await db.query(`
      UPDATE conceptos_gasto SET categoria_gasto_id=?, codigo=?, nombre=?, descripcion=?, requiere_factura=?, activo=? WHERE concepto_gasto_id=?
    `, [d.categoria_gasto_id, d.codigo, d.nombre, d.descripcion, d.requiere_factura, d.activo, req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

app.delete('/api/conceptos-gasto/:id', async (req, res) => {
  try {
    await db.query('UPDATE conceptos_gasto SET activo = "N" WHERE concepto_gasto_id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});
// ==================== GASTOS ====================

app.get('/api/gastos/kpis/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        
        const [hoyResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total
            FROM gastos WHERE empresa_id = ? AND activo = 'Y' AND DATE(fecha) = CURDATE()
        `, [empresaId]);
        
        const [semanaResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total
            FROM gastos WHERE empresa_id = ? AND activo = 'Y' 
            AND YEARWEEK(fecha, 1) = YEARWEEK(CURDATE(), 1)
        `, [empresaId]);
        
        const [mesResult] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as registros
            FROM gastos WHERE empresa_id = ? AND activo = 'Y'
            AND YEAR(fecha) = YEAR(CURDATE()) AND MONTH(fecha) = MONTH(CURDATE())
        `, [empresaId]);
        
        const [porCategoria] = await db.query(`
            SELECT COALESCE(cg.nombre, 'Sin categoría') as categoria, COALESCE(SUM(g.total), 0) as total
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            WHERE g.empresa_id = ? AND g.activo = 'Y'
            AND YEAR(g.fecha) = YEAR(CURDATE()) AND MONTH(g.fecha) = MONTH(CURDATE())
            GROUP BY g.categoria_gasto_id ORDER BY total DESC LIMIT 8
        `, [empresaId]);
        
        const [porDia] = await db.query(`
            SELECT DATE_FORMAT(fecha, '%d/%m') as dia, COALESCE(SUM(total), 0) as total
            FROM gastos WHERE empresa_id = ? AND activo = 'Y'
            AND fecha >= DATE_SUB(CURDATE(), INTERVAL 6 DAY)
            GROUP BY DATE(fecha) ORDER BY fecha ASC
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
    } catch (e) {
        console.error('Error KPIs gastos:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/gastos/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        const { desde, hasta, categoria, estado, page = 1, limit = 20 } = req.query;
        const offset = (page - 1) * limit;
        
        let where = 'g.empresa_id = ? AND g.activo = "Y"';
        const params = [empresaId];
        
        if (desde) { where += ' AND g.fecha >= ?'; params.push(desde); }
        if (hasta) { where += ' AND g.fecha <= ?'; params.push(hasta); }
        if (categoria) { where += ' AND g.categoria_gasto_id = ?'; params.push(categoria); }
        if (estado) { where += ' AND g.estado = ?'; params.push(estado); }
        
        const [countResult] = await db.query(`SELECT COUNT(*) as total FROM gastos g WHERE ${where}`, params);
        
        const [gastos] = await db.query(`
            SELECT g.*, cg.nombre as categoria_nombre, co.nombre as concepto_nombre,
                   mp.nombre as metodo_pago_nombre, s.nombre as sucursal_nombre
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            LEFT JOIN conceptos_gasto co ON g.concepto_gasto_id = co.concepto_gasto_id
            LEFT JOIN metodos_pago mp ON g.metodo_pago_id = mp.metodo_pago_id
            LEFT JOIN sucursales s ON g.sucursal_id = s.sucursal_id
            WHERE ${where} ORDER BY g.fecha DESC, g.gasto_id DESC LIMIT ? OFFSET ?
        `, [...params, parseInt(limit), parseInt(offset)]);
        
        const [totalesResult] = await db.query(`
            SELECT COALESCE(SUM(subtotal), 0) as subtotal, COALESCE(SUM(iva), 0) as iva, COALESCE(SUM(total), 0) as total
            FROM gastos g WHERE ${where}
        `, params);
        
        res.json({ success: true, gastos, total: countResult[0].total, totales: totalesResult[0] });
    } catch (e) {
        console.error('Error gastos:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/gastos', async (req, res) => {
    try {
        const d = req.body;
        const [result] = await db.query(`
            INSERT INTO gastos (
                empresa_id, sucursal_id, categoria_gasto_id, concepto_gasto_id,
                fecha, numero_documento, descripcion, proveedor_id, proveedor_nombre,
                subtotal, iva, isr_retenido, iva_retenido, total,
                metodo_pago_id, cuenta_bancaria_id, referencia_pago,
                tiene_factura, uuid_factura, estado
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            d.empresa_id, d.sucursal_id || null, d.categoria_gasto_id || null, d.concepto_gasto_id || null,
            d.fecha, d.numero_documento, d.descripcion, d.proveedor_id || null, d.proveedor_nombre,
            d.subtotal || 0, d.iva || 0, d.isr_retenido || 0, d.iva_retenido || 0, d.total || 0,
            d.metodo_pago_id || null, d.cuenta_bancaria_id || null, d.referencia_pago,
            d.tiene_factura || 'N', d.uuid_factura, d.estado || 'PAGADO'
        ]);
        res.json({ success: true, gasto_id: result.insertId });
    } catch (e) {
        console.error('Error crear gasto:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

app.put('/api/gastos/:id', async (req, res) => {
    try {
        const d = req.body;
        await db.query(`
            UPDATE gastos SET
                sucursal_id=?, categoria_gasto_id=?, concepto_gasto_id=?,
                fecha=?, numero_documento=?, descripcion=?, proveedor_id=?, proveedor_nombre=?,
                subtotal=?, iva=?, isr_retenido=?, iva_retenido=?, total=?,
                metodo_pago_id=?, cuenta_bancaria_id=?, referencia_pago=?,
                tiene_factura=?, uuid_factura=?, estado=?
            WHERE gasto_id=?
        `, [
            d.sucursal_id || null, d.categoria_gasto_id || null, d.concepto_gasto_id || null,
            d.fecha, d.numero_documento, d.descripcion, d.proveedor_id || null, d.proveedor_nombre,
            d.subtotal || 0, d.iva || 0, d.isr_retenido || 0, d.iva_retenido || 0, d.total || 0,
            d.metodo_pago_id || null, d.cuenta_bancaria_id || null, d.referencia_pago,
            d.tiene_factura || 'N', d.uuid_factura, d.estado || 'PAGADO',
            req.params.id
        ]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.delete('/api/gastos/:id', async (req, res) => {
    try {
        await db.query('UPDATE gastos SET activo = "N" WHERE gasto_id = ?', [req.params.id]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/api/gastos/exportar/:empresaId', async (req, res) => {
    try {
        const { empresaId } = req.params;
        const { desde, hasta } = req.query;
        
        let where = 'g.empresa_id = ? AND g.activo = "Y"';
        const params = [empresaId];
        if (desde) { where += ' AND g.fecha >= ?'; params.push(desde); }
        if (hasta) { where += ' AND g.fecha <= ?'; params.push(hasta); }
        
        const [gastos] = await db.query(`
            SELECT g.fecha, g.numero_documento, cg.nombre as categoria, co.nombre as concepto,
                   g.descripcion, g.proveedor_nombre, g.subtotal, g.iva, g.total, g.estado,
                   CASE WHEN g.tiene_factura = 'Y' THEN 'Sí' ELSE 'No' END as factura
            FROM gastos g
            LEFT JOIN categorias_gasto cg ON g.categoria_gasto_id = cg.categoria_gasto_id
            LEFT JOIN conceptos_gasto co ON g.concepto_gasto_id = co.concepto_gasto_id
            WHERE ${where} ORDER BY g.fecha DESC
        `, params);
        
        let csv = 'Fecha,Documento,Categoría,Concepto,Descripción,Proveedor,Subtotal,IVA,Total,Estado,Factura\n';
        gastos.forEach(g => {
            csv += `${g.fecha},${g.numero_documento || ''},${g.categoria || ''},${g.concepto || ''},"${(g.descripcion || '').replace(/"/g, '""')}",${g.proveedor_nombre || ''},${g.subtotal},${g.iva},${g.total},${g.estado},${g.factura}\n`;
        });
        
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename=gastos_${desde}_${hasta}.csv`);
        res.send('\uFEFF' + csv);
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});


// ==================== COMPRAS ====================

// Listar compras
app.get('/api/compras/:empresaID', async (req, res) => {
    try {
        const { desde, hasta, proveedor, estatus, tipo } = req.query;
        let query = `
            SELECT c.*, p.nombre_comercial as proveedor_nombre, u.nombre as usuario_nombre,
                   s.nombre as sucursal_nombre,
                   (SELECT COUNT(*) FROM detalle_compra WHERE compra_id = c.compra_id) as num_productos
            FROM compras c
            LEFT JOIN proveedores p ON c.proveedor_id = p.proveedor_id
            LEFT JOIN usuarios u ON c.usuario_id = u.usuario_id
            LEFT JOIN sucursales s ON c.sucursal_id = s.sucursal_id
            WHERE c.empresa_id = ?
        `;
        const params = [req.params.empresaID];
        
        if (desde) { query += ' AND DATE(c.fecha) >= ?'; params.push(desde); }
        if (hasta) { query += ' AND DATE(c.fecha) <= ?'; params.push(hasta); }
        if (proveedor) { query += ' AND c.proveedor_id = ?'; params.push(proveedor); }
        if (estatus) { query += ' AND c.estatus = ?'; params.push(estatus); }
        if (tipo) { query += ' AND c.tipo = ?'; params.push(tipo); }
        
        query += ' ORDER BY c.fecha DESC LIMIT 500';
        
        const [compras] = await db.query(query, params);
        res.json({ success: true, compras });
    } catch (e) {
        console.error('Error compras:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// Detalle completo de compra
app.get('/api/compras/detalle/:compraID', async (req, res) => {
    try {
        const { compraID } = req.params;
        
        const [compras] = await db.query(`
            SELECT c.*, p.nombre_comercial as proveedor_nombre, p.rfc as proveedor_rfc,
                   p.telefono as proveedor_telefono, p.email as proveedor_email,
                   u.nombre as usuario_nombre, s.nombre as sucursal_nombre,
                   a.nombre as almacen_nombre
            FROM compras c
            LEFT JOIN proveedores p ON c.proveedor_id = p.proveedor_id
            LEFT JOIN usuarios u ON c.usuario_id = u.usuario_id
            LEFT JOIN sucursales s ON c.sucursal_id = s.sucursal_id
            LEFT JOIN almacenes a ON c.almacen_id = a.almacen_id
            WHERE c.compra_id = ?
        `, [compraID]);
        
        if (compras.length === 0) {
            return res.status(404).json({ success: false, error: 'Compra no encontrada' });
        }
        
        const [productos] = await db.query(`
            SELECT d.*, pr.nombre as producto_nombre, pr.codigo_barras
            FROM detalle_compra d
            LEFT JOIN productos pr ON d.producto_id = pr.producto_id
            WHERE d.compra_id = ?
        `, [compraID]);
        
        const [pagos] = await db.query(`
            SELECT pc.*, mp.nombre as metodo_nombre, u.nombre as usuario_nombre
            FROM pago_compras pc
            LEFT JOIN metodos_pago mp ON pc.metodo_pago_id = mp.metodo_pago_id
            LEFT JOIN usuarios u ON pc.usuario_id = u.usuario_id
            WHERE pc.compra_id = ? AND pc.estatus = 'APLICADO'
            ORDER BY pc.fecha_pago DESC
        `, [compraID]);
        
        res.json({ success: true, compra: compras[0], productos, pagos });
    } catch (e) {
        console.error('Error detalle compra:', e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// Crear compra
app.post('/api/compras', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const d = req.body;
        const compraId = generarID('COM');
        
        const [folioRes] = await conn.query(
            'SELECT COALESCE(MAX(CAST(folio AS UNSIGNED)), 0) + 1 as siguiente FROM compras WHERE empresa_id = ? AND tipo = ?',
            [d.empresa_id, d.tipo || 'COMPRA']
        );
        const folio = folioRes[0].siguiente;
        
        await conn.query(`
            INSERT INTO compras (
                compra_id, empresa_id, sucursal_id, almacen_id, proveedor_id, usuario_id,
                tipo, serie, folio, fecha, fecha_entrega, fecha_vencimiento,
                moneda_id, tipo_cambio, subtotal, descuento, impuestos, total, saldo,
                notas, estatus, factura_uuid
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            compraId, d.empresa_id, d.sucursal_id, d.almacen_id, d.proveedor_id, d.usuario_id,
            d.tipo || 'COMPRA', d.serie || 'C', folio, d.fecha_entrega, d.fecha_vencimiento,
            d.moneda_id || 'MXN', d.tipo_cambio || 1, d.subtotal || 0, d.descuento || 0,
            d.impuestos || 0, d.total || 0, d.total || 0,
            d.notas, d.estatus || 'BORRADOR', d.factura_uuid
        ]);
        
        if (d.productos && d.productos.length > 0) {
            for (const item of d.productos) {
                const detalleId = generarID('DCOM');
                await conn.query(`
                    INSERT INTO detalle_compra (
                        detalle_id, compra_id, producto_id, descripcion, cantidad, cantidad_recibida,
                        unidad_id, costo_unitario, descuento_pct, descuento_monto,
                        impuesto_pct, impuesto_monto, subtotal, lote, fecha_caducidad
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [
                    detalleId, compraId, item.producto_id, item.descripcion, item.cantidad, 0,
                    item.unidad_id || 'PZ', item.costo_unitario, item.descuento_pct || 0,
                    item.descuento_monto || 0, item.impuesto_pct || 0, item.impuesto_monto || 0,
                    item.subtotal, item.lote, item.fecha_caducidad
                ]);
            }
        }
        
        await conn.commit();
        res.json({ success: true, compra_id: compraId, folio });
    } catch (e) {
        await conn.rollback();
        console.error('Error crear compra:', e);
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});

// Actualizar compra - CORREGIDO
app.put('/api/compras/:compraID', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const { compraID } = req.params;
        const d = req.body;
        
        // Obtener suma de pagos aplicados
        const [pagosRes] = await conn.query(`
            SELECT COALESCE(SUM(monto), 0) as total_pagado 
            FROM pago_compras 
            WHERE compra_id = ? AND estatus = 'APLICADO'
        `, [compraID]);
        const totalPagado = parseFloat(pagosRes[0].total_pagado) || 0;
        
        // Calcular nuevo saldo si viene total
        let nuevoSaldo = null;
        if (d.total !== undefined) {
            nuevoSaldo = Math.max(0, parseFloat(d.total) - totalPagado);
        }
        
        await conn.query(`
            UPDATE compras SET
                proveedor_id = COALESCE(?, proveedor_id), 
                almacen_id = COALESCE(?, almacen_id), 
                fecha_entrega = COALESCE(?, fecha_entrega), 
                fecha_vencimiento = COALESCE(?, fecha_vencimiento),
                moneda_id = COALESCE(?, moneda_id), 
                tipo_cambio = COALESCE(?, tipo_cambio), 
                subtotal = COALESCE(?, subtotal), 
                descuento = COALESCE(?, descuento),
                impuestos = COALESCE(?, impuestos), 
                total = COALESCE(?, total), 
                saldo = COALESCE(?, saldo),
                notas = COALESCE(?, notas), 
                estatus = COALESCE(?, estatus), 
                factura_uuid = COALESCE(?, factura_uuid)
            WHERE compra_id = ?
        `, [
            d.proveedor_id, d.almacen_id, d.fecha_entrega, d.fecha_vencimiento,
            d.moneda_id, d.tipo_cambio, d.subtotal, d.descuento,
            d.impuestos, d.total, nuevoSaldo,
            d.notas, d.estatus, d.factura_uuid,
            compraID
        ]);
        
        // Si se actualizan productos, recalcular todo
        if (d.productos !== undefined) {
            await conn.query('DELETE FROM detalle_compra WHERE compra_id = ?', [compraID]);
            
            if (d.productos && d.productos.length > 0) {
                for (const item of d.productos) {
                    const detalleId = generarID('DCOM');
                    await conn.query(`
                        INSERT INTO detalle_compra (
                            detalle_id, compra_id, producto_id, descripcion, cantidad, cantidad_recibida,
                            unidad_id, costo_unitario, descuento_pct, descuento_monto,
                            impuesto_pct, impuesto_monto, subtotal, lote, fecha_caducidad
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    `, [
                        detalleId, compraID, item.producto_id, item.descripcion, item.cantidad,
                        item.cantidad_recibida || 0, item.unidad_id || 'PZ', item.costo_unitario,
                        item.descuento_pct || 0, item.descuento_monto || 0, 
                        item.impuesto_pct || 0, item.impuesto_monto || 0,
                        item.subtotal, item.lote, item.fecha_caducidad
                    ]);
                }
            }
        }
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        console.error('Error actualizar compra:', e);
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});




// Recibir mercancía
app.post('/api/compras/recibir/:compraID', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const { compraID } = req.params;
        const { productos, usuario_id } = req.body;
        
        let todoRecibido = true;
        
        for (const item of productos) {
            await conn.query(`
                UPDATE detalle_compra SET cantidad_recibida = cantidad_recibida + ?
                WHERE detalle_id = ?
            `, [item.cantidad_recibir, item.detalle_id]);
            
            const [det] = await conn.query(
                'SELECT cantidad, cantidad_recibida FROM detalle_compra WHERE detalle_id = ?',
                [item.detalle_id]
            );
            
            if (det.length > 0 && parseFloat(det[0].cantidad_recibida) < parseFloat(det[0].cantidad)) {
                todoRecibido = false;
            }
        }
        
        const nuevoEstatus = todoRecibido ? 'RECIBIDA' : 'PARCIAL';
        await conn.query('UPDATE compras SET estatus = ? WHERE compra_id = ?', [nuevoEstatus, compraID]);
        
        await conn.commit();
        res.json({ success: true, estatus: nuevoEstatus });
    } catch (e) {
        await conn.rollback();
        console.error('Error recibir:', e);
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});

// Cancelar compra
app.put('/api/compras/cancelar/:compraID', async (req, res) => {
    try {
        const { compraID } = req.params;
        await db.query('UPDATE compras SET estatus = "CANCELADA" WHERE compra_id = ?', [compraID]);
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Eliminar compra (solo borrador)
app.delete('/api/compras/:compraID', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const { compraID } = req.params;
        
        const [compra] = await conn.query('SELECT estatus FROM compras WHERE compra_id = ?', [compraID]);
        if (compra.length === 0) {
            return res.status(404).json({ success: false, error: 'Compra no encontrada' });
        }
        if (compra[0].estatus !== 'BORRADOR') {
            return res.status(400).json({ success: false, error: 'Solo se pueden eliminar compras en borrador' });
        }
        
        await conn.query('DELETE FROM detalle_compra WHERE compra_id = ?', [compraID]);
        await conn.query('DELETE FROM compras WHERE compra_id = ?', [compraID]);
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});

// ==================== PAGOS COMPRAS ====================

// Listar pagos de una compra
app.get('/api/pago-compras/compra/:compraID', async (req, res) => {
    try {
        const [pagos] = await db.query(`
            SELECT pc.*, mp.nombre as metodo_nombre, cb.banco, u.nombre as usuario_nombre
            FROM pago_compras pc
            LEFT JOIN metodos_pago mp ON pc.metodo_pago_id = mp.metodo_pago_id
            LEFT JOIN cuentas_bancarias cb ON pc.cuenta_bancaria_id = cb.cuenta_id
            LEFT JOIN usuarios u ON pc.usuario_id = u.usuario_id
            WHERE pc.compra_id = ?
            ORDER BY pc.fecha_pago DESC
        `, [req.params.compraID]);
        res.json({ success: true, pagos });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Listar pagos por proveedor
app.get('/api/pago-compras/proveedor/:proveedorID', async (req, res) => {
    try {
        const { desde, hasta } = req.query;
        let query = `
            SELECT pc.*, c.folio as compra_folio, mp.nombre as metodo_nombre
            FROM pago_compras pc
            LEFT JOIN compras c ON pc.compra_id = c.compra_id
            LEFT JOIN metodos_pago mp ON pc.metodo_pago_id = mp.metodo_pago_id
            WHERE pc.proveedor_id = ? AND pc.estatus = 'APLICADO'
        `;
        const params = [req.params.proveedorID];
        
        if (desde) { query += ' AND DATE(pc.fecha_pago) >= ?'; params.push(desde); }
        if (hasta) { query += ' AND DATE(pc.fecha_pago) <= ?'; params.push(hasta); }
        
        query += ' ORDER BY pc.fecha_pago DESC';
        
        const [pagos] = await db.query(query, params);
        res.json({ success: true, pagos });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Registrar pago
app.post('/api/pago-compras', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const d = req.body;
        const pagoId = generarID('PCOM');
        
        await conn.query(`
            INSERT INTO pago_compras (
                pago_compra_id, empresa_id, sucursal_id, compra_id, proveedor_id,
                metodo_pago_id, cuenta_bancaria_id, monto, fecha_pago, fecha_vencimiento,
                referencia, notas, comprobante_url, usuario_id, estatus
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?, ?, 'APLICADO')
        `, [
            pagoId, d.empresa_id, d.sucursal_id, d.compra_id, d.proveedor_id,
            d.metodo_pago_id, d.cuenta_bancaria_id, d.monto, d.fecha_vencimiento,
            d.referencia, d.notas, d.comprobante_url, d.usuario_id
        ]);
        
        await conn.query(`
            UPDATE compras SET saldo = saldo - ? WHERE compra_id = ?
        `, [d.monto, d.compra_id]);
        
        const [compra] = await conn.query('SELECT saldo FROM compras WHERE compra_id = ?', [d.compra_id]);
        if (compra.length > 0 && parseFloat(compra[0].saldo) <= 0) {
            await conn.query('UPDATE compras SET saldo = 0 WHERE compra_id = ?', [d.compra_id]);
        }
        
        await conn.commit();
        res.json({ success: true, pago_compra_id: pagoId });
    } catch (e) {
        await conn.rollback();
        console.error('Error pago compra:', e);
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});

// Cancelar pago
app.put('/api/pago-compras/cancelar/:pagoID', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        
        const { pagoID } = req.params;
        
        const [pago] = await conn.query('SELECT * FROM pago_compras WHERE pago_compra_id = ?', [pagoID]);
        if (pago.length === 0) {
            return res.status(404).json({ success: false, error: 'Pago no encontrado' });
        }
        
        await conn.query('UPDATE pago_compras SET estatus = "CANCELADO" WHERE pago_compra_id = ?', [pagoID]);
        
        await conn.query('UPDATE compras SET saldo = saldo + ? WHERE compra_id = ?', [pago[0].monto, pago[0].compra_id]);
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally {
        conn.release();
    }
});

// KPIs compras
app.get('/api/compras/kpis/:empresaID', async (req, res) => {
    try {
        const { empresaID } = req.params;
        
        const [hoy] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as cantidad
            FROM compras WHERE empresa_id = ? AND DATE(fecha) = CURDATE() AND estatus != 'CANCELADA'
        `, [empresaID]);
        
        const [mes] = await db.query(`
            SELECT COALESCE(SUM(total), 0) as total, COUNT(*) as cantidad
            FROM compras WHERE empresa_id = ? AND MONTH(fecha) = MONTH(CURDATE()) 
            AND YEAR(fecha) = YEAR(CURDATE()) AND estatus != 'CANCELADA'
        `, [empresaID]);
        
        const [pendientes] = await db.query(`
            SELECT COALESCE(SUM(saldo), 0) as total, COUNT(*) as cantidad
            FROM compras WHERE empresa_id = ? AND saldo > 0 AND estatus != 'CANCELADA'
        `, [empresaID]);
        
        const [porRecibir] = await db.query(`
            SELECT COUNT(*) as cantidad
            FROM compras WHERE empresa_id = ? AND estatus IN ('PENDIENTE', 'PARCIAL')
        `, [empresaID]);
        
        res.json({
            success: true,
            hoy: hoy[0],
            mes: mes[0],
            pendientes: pendientes[0],
            por_recibir: porRecibir[0].cantidad
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// Cuentas por pagar (resumen por proveedor)
app.get('/api/compras/cuentas-pagar/:empresaID', async (req, res) => {
    try {
        const [cuentas] = await db.query(`
            SELECT p.proveedor_id, p.nombre_comercial as proveedor_nombre,
                   COUNT(c.compra_id) as num_compras,
                   COALESCE(SUM(c.saldo), 0) as saldo_total,
                   MIN(c.fecha_vencimiento) as proxima_vencimiento
            FROM proveedores p
            LEFT JOIN compras c ON p.proveedor_id = c.proveedor_id 
                AND c.saldo > 0 AND c.estatus != 'CANCELADA'
            WHERE p.empresa_id = ? AND p.activo = 'Y'
            GROUP BY p.proveedor_id, p.nombre_comercial
            HAVING saldo_total > 0
            ORDER BY saldo_total DESC
        `, [req.params.empresaID]);
        
        res.json({ success: true, cuentas });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// ==================== CONCEPTOS INVENTARIO ====================
app.get('/api/conceptos-inventario/:empresaID', async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT * FROM conceptos_inventario 
            WHERE empresa_id = ? AND activo = 'Y'
            ORDER BY tipo, nombre
        `, [req.params.empresaID]);
        res.json({ success: true, conceptos: rows });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ==================== INVENTARIO (EXISTENCIAS) ====================
app.get('/api/inventario/:empresaID', async (req, res) => {
    try {
        const { almacen_id } = req.query;
        let sql = `
            SELECT i.*, p.nombre as producto_nombre, p.codigo_barras, p.codigo_interno, p.stock_minimo,
                   a.nombre as almacen_nombre
            FROM inventario i
            JOIN productos p ON i.producto_id = p.producto_id
            JOIN almacenes a ON i.almacen_id = a.almacen_id
            WHERE i.empresa_id = ?
        `;
        const params = [req.params.empresaID];
        if (almacen_id) { sql += ' AND i.almacen_id = ?'; params.push(almacen_id); }
        sql += ' ORDER BY p.nombre';
        
        const [rows] = await db.query(sql, params);
        res.json({ success: true, inventario: rows });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// ==================== MOVIMIENTOS INVENTARIO ====================
app.get('/api/movimientos-inventario/:empresaID', async (req, res) => {
    try {
        const { almacen_id, concepto_id, tipo, desde, hasta } = req.query;
        let sql = `
            SELECT m.*, p.nombre as producto_nombre, a.nombre as almacen_nombre,
                   c.nombre as concepto_nombre, c.tipo as concepto_tipo, u.nombre as usuario_nombre
            FROM movimientos_inventario m
            JOIN productos p ON m.producto_id = p.producto_id
            JOIN almacenes a ON m.almacen_id = a.almacen_id
            JOIN conceptos_inventario c ON m.concepto_id = c.concepto_id
            LEFT JOIN usuarios u ON m.usuario_id = u.usuario_id
            WHERE m.empresa_id = ?
        `;
        const params = [req.params.empresaID];
        if (almacen_id) { sql += ' AND m.almacen_id = ?'; params.push(almacen_id); }
        if (concepto_id) { sql += ' AND m.concepto_id = ?'; params.push(concepto_id); }
        if (tipo) { sql += ' AND c.tipo = ?'; params.push(tipo); }
        if (desde) { sql += ' AND DATE(m.fecha) >= ?'; params.push(desde); }
        if (hasta) { sql += ' AND DATE(m.fecha) <= ?'; params.push(hasta); }
        sql += ' ORDER BY m.fecha DESC LIMIT 500';
        
        const [rows] = await db.query(sql, params);
        res.json({ success: true, movimientos: rows });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

// APLICAR AJUSTE DE INVENTARIO
app.post('/api/movimientos-inventario/ajuste', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        const { empresa_id, sucursal_id, almacen_id, concepto_id, usuario_id, fecha, referencia, notas, productos } = req.body;
        
        // Obtener tipo del concepto
        const [concRow] = await conn.query('SELECT tipo FROM conceptos_inventario WHERE concepto_id = ?', [concepto_id]);
        const tipoConcepto = concRow[0]?.tipo || 'ENTRADA';
        
        for (const item of productos) {
            const movId = 'MOV' + Date.now() + Math.random().toString(36).substr(2, 5);
            
            // Obtener existencia actual
            const [invRow] = await conn.query(
                'SELECT stock, costo_promedio FROM inventario WHERE almacen_id = ? AND producto_id = ?',
                [almacen_id, item.producto_id]
            );
            const existAnterior = invRow[0]?.stock || 0;
            const costoAnterior = invRow[0]?.costo_promedio || item.costo_unitario;
            
            // Calcular nueva existencia
            const cantidad = tipoConcepto === 'ENTRADA' ? item.cantidad : -item.cantidad;
            const existNueva = parseFloat(existAnterior) + cantidad;
            
            // Calcular nuevo costo promedio (solo para entradas)
            let nuevoCosto = costoAnterior;
            if (tipoConcepto === 'ENTRADA' && item.costo_unitario > 0) {
                const valorAnterior = existAnterior * costoAnterior;
                const valorNuevo = item.cantidad * item.costo_unitario;
                nuevoCosto = existNueva > 0 ? (valorAnterior + valorNuevo) / existNueva : item.costo_unitario;
            }
            
            // Insertar movimiento
            await conn.query(`
                INSERT INTO movimientos_inventario 
                (movimiento_id, empresa_id, sucursal_id, almacen_id, concepto_id, producto_id, 
                 cantidad, costo_unitario, costo_total, existencia_anterior, existencia_nueva,
                 referencia_tipo, referencia_id, fecha, usuario_id, notas)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'AJUSTE', ?, ?, ?, ?)
            `, [movId, empresa_id, sucursal_id, almacen_id, concepto_id, item.producto_id,
                cantidad, item.costo_unitario, Math.abs(cantidad) * item.costo_unitario,
                existAnterior, existNueva, referencia, fecha || new Date(), usuario_id, notas]);
            
            // Actualizar o insertar inventario
            if (invRow.length > 0) {
                await conn.query(`
                    UPDATE inventario SET stock = ?, costo_promedio = ?, ultimo_movimiento = NOW()
                    WHERE almacen_id = ? AND producto_id = ?
                `, [existNueva, nuevoCosto, almacen_id, item.producto_id]);
            } else {
                const invId = 'INV' + Date.now() + Math.random().toString(36).substr(2, 5);
                await conn.query(`
                    INSERT INTO inventario (inventario_id, empresa_id, almacen_id, producto_id, stock, costo_promedio, ultimo_movimiento)
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                `, [invId, empresa_id, almacen_id, item.producto_id, existNueva, item.costo_unitario]);
            }
        }
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally { conn.release(); }
});

// ==================== TRASPASOS ====================
app.get('/api/traspasos/:empresaID', async (req, res) => {
    try {
        const { estatus, almacen_origen_id, almacen_destino_id } = req.query;
        let sql = `
            SELECT t.*, ao.nombre as almacen_origen_nombre, ad.nombre as almacen_destino_nombre,
                   (SELECT COUNT(*) FROM detalle_traspaso WHERE traspaso_id = t.traspaso_id) as total_productos
            FROM traspasos t
            JOIN almacenes ao ON t.almacen_origen_id = ao.almacen_id
            JOIN almacenes ad ON t.almacen_destino_id = ad.almacen_id
            WHERE t.empresa_id = ?
        `;
        const params = [req.params.empresaID];
        if (estatus) { sql += ' AND t.estatus = ?'; params.push(estatus); }
        if (almacen_origen_id) { sql += ' AND t.almacen_origen_id = ?'; params.push(almacen_origen_id); }
        if (almacen_destino_id) { sql += ' AND t.almacen_destino_id = ?'; params.push(almacen_destino_id); }
        sql += ' ORDER BY t.fecha_solicitud DESC';
        
        const [rows] = await db.query(sql, params);
        res.json({ success: true, traspasos: rows });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.get('/api/traspasos/detalle/:traspasoID', async (req, res) => {
    try {
        const [traspaso] = await db.query(`
            SELECT t.*, ao.nombre as almacen_origen_nombre, ad.nombre as almacen_destino_nombre
            FROM traspasos t
            JOIN almacenes ao ON t.almacen_origen_id = ao.almacen_id
            JOIN almacenes ad ON t.almacen_destino_id = ad.almacen_id
            WHERE t.traspaso_id = ?
        `, [req.params.traspasoID]);
        
        const [productos] = await db.query(`
            SELECT dt.*, p.nombre as producto_nombre, p.codigo_barras,
                   COALESCE(i.stock_disponible, i.stock, 0) as stock_disponible
            FROM detalle_traspaso dt
            JOIN productos p ON dt.producto_id = p.producto_id
            LEFT JOIN inventario i ON dt.producto_id = i.producto_id 
                AND i.almacen_id = (SELECT almacen_origen_id FROM traspasos WHERE traspaso_id = ?)
            WHERE dt.traspaso_id = ?
        `, [req.params.traspasoID, req.params.traspasoID]);
        
        res.json({ success: true, traspaso: traspaso[0], productos });
    } catch (e) { res.status(500).json({ success: false, error: e.message }); }
});

app.post('/api/traspasos', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        const d = req.body;
        const traspasoId = 'TRA' + Date.now();
        
        await conn.query(`
            INSERT INTO traspasos (traspaso_id, empresa_id, almacen_origen_id, almacen_destino_id, 
                usuario_id, referencia, notas, estatus)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [traspasoId, d.empresa_id, d.almacen_origen_id, d.almacen_destino_id,
            d.usuario_id, d.referencia, d.notas, d.estatus || 'BORRADOR']);
        
        for (const item of d.productos) {
            const detalleId = 'DTRA' + Date.now() + Math.random().toString(36).substr(2, 5);
            await conn.query(`
                INSERT INTO detalle_traspaso (detalle_id, traspaso_id, producto_id, cantidad_solicitada, costo_unitario)
                VALUES (?, ?, ?, ?, ?)
            `, [detalleId, traspasoId, item.producto_id, item.cantidad_solicitada, item.costo_unitario || 0]);
        }
        
        await conn.commit();
        res.json({ success: true, traspaso_id: traspasoId });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally { conn.release(); }
});

app.put('/api/traspasos/:traspasoID', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        const d = req.body;
        
        await conn.query(`
            UPDATE traspasos SET 
                almacen_origen_id = COALESCE(?, almacen_origen_id),
                almacen_destino_id = COALESCE(?, almacen_destino_id),
                referencia = COALESCE(?, referencia),
                notas = COALESCE(?, notas),
                estatus = COALESCE(?, estatus)
            WHERE traspaso_id = ?
        `, [d.almacen_origen_id, d.almacen_destino_id, d.referencia, d.notas, d.estatus, req.params.traspasoID]);
        
        if (d.productos) {
            await conn.query('DELETE FROM detalle_traspaso WHERE traspaso_id = ?', [req.params.traspasoID]);
            for (const item of d.productos) {
                const detalleId = 'DTRA' + Date.now() + Math.random().toString(36).substr(2, 5);
                await conn.query(`
                    INSERT INTO detalle_traspaso (detalle_id, traspaso_id, producto_id, cantidad_solicitada, 
                        cantidad_enviada, cantidad_recibida, costo_unitario)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [detalleId, req.params.traspasoID, item.producto_id, item.cantidad_solicitada,
                    item.cantidad_enviada || 0, item.cantidad_recibida || 0, item.costo_unitario || 0]);
            }
        }
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally { conn.release(); }
});

// ENVIAR TRASPASO (descuenta stock origen)
app.post('/api/traspasos/:traspasoID/enviar', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        const { usuario_id, productos } = req.body;
        const traspasoId = req.params.traspasoID;
        
        // Obtener datos del traspaso
        const [trasRow] = await conn.query('SELECT * FROM traspasos WHERE traspaso_id = ?', [traspasoId]);
        const traspaso = trasRow[0];
        
        // Obtener concepto SAL_TRA
        const [concRow] = await conn.query(
            "SELECT concepto_id FROM conceptos_inventario WHERE empresa_id = ? AND codigo LIKE '%SAL%TRA%' LIMIT 1",
            [traspaso.empresa_id]
        );
        const conceptoSalida = concRow[0]?.concepto_id;
        
        for (const item of productos) {
            // Actualizar detalle
            await conn.query(
                'UPDATE detalle_traspaso SET cantidad_enviada = ? WHERE traspaso_id = ? AND producto_id = ?',
                [item.cantidad_enviada, traspasoId, item.producto_id]
            );
            
            // Obtener existencia actual
            const [invRow] = await conn.query(
                'SELECT stock FROM inventario WHERE almacen_id = ? AND producto_id = ?',
                [traspaso.almacen_origen_id, item.producto_id]
            );
            const existAnterior = invRow[0]?.stock || 0;
            const existNueva = existAnterior - item.cantidad_enviada;
            
            // Crear movimiento de salida
            const movId = 'MOV' + Date.now() + Math.random().toString(36).substr(2, 5);
            await conn.query(`
                INSERT INTO movimientos_inventario 
                (movimiento_id, empresa_id, sucursal_id, almacen_id, concepto_id, producto_id,
                 cantidad, costo_unitario, existencia_anterior, existencia_nueva,
                 referencia_tipo, referencia_id, usuario_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'TRASPASO', ?, ?)
            `, [movId, traspaso.empresa_id, traspaso.empresa_id, traspaso.almacen_origen_id,
                conceptoSalida, item.producto_id, -item.cantidad_enviada, item.costo_unitario,
                existAnterior, existNueva, traspasoId, usuario_id]);
            
            // Actualizar inventario origen
            await conn.query(
                'UPDATE inventario SET stock = ?, ultimo_movimiento = NOW() WHERE almacen_id = ? AND producto_id = ?',
                [existNueva, traspaso.almacen_origen_id, item.producto_id]
            );
        }
        
        // Actualizar estatus traspaso
        await conn.query(
            'UPDATE traspasos SET estatus = ?, fecha_envio = NOW() WHERE traspaso_id = ?',
            ['EN_TRANSITO', traspasoId]
        );
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally { conn.release(); }
});

// RECIBIR TRASPASO (suma stock destino)
app.post('/api/traspasos/:traspasoID/recibir', async (req, res) => {
    const conn = await db.getConnection();
    try {
        await conn.beginTransaction();
        const { usuario_id, productos } = req.body;
        const traspasoId = req.params.traspasoID;
        
        // Obtener datos del traspaso
        const [trasRow] = await conn.query('SELECT * FROM traspasos WHERE traspaso_id = ?', [traspasoId]);
        const traspaso = trasRow[0];
        
        // Obtener concepto ENT_TRA
        const [concRow] = await conn.query(
            "SELECT concepto_id FROM conceptos_inventario WHERE empresa_id = ? AND codigo LIKE '%ENT%TRA%' LIMIT 1",
            [traspaso.empresa_id]
        );
        const conceptoEntrada = concRow[0]?.concepto_id;
        
        for (const item of productos) {
            // Actualizar detalle
            await conn.query(
                'UPDATE detalle_traspaso SET cantidad_recibida = ? WHERE traspaso_id = ? AND producto_id = ?',
                [item.cantidad_recibida, traspasoId, item.producto_id]
            );
            
            // Obtener existencia actual en destino
            const [invRow] = await conn.query(
                'SELECT inventario_id, stock, costo_promedio FROM inventario WHERE almacen_id = ? AND producto_id = ?',
                [traspaso.almacen_destino_id, item.producto_id]
            );
            
            const existAnterior = invRow[0]?.stock || 0;
            const existNueva = parseFloat(existAnterior) + item.cantidad_recibida;
            
            // Crear movimiento de entrada
            const movId = 'MOV' + Date.now() + Math.random().toString(36).substr(2, 5);
            await conn.query(`
                INSERT INTO movimientos_inventario 
                (movimiento_id, empresa_id, sucursal_id, almacen_id, concepto_id, producto_id,
                 cantidad, costo_unitario, existencia_anterior, existencia_nueva,
                 referencia_tipo, referencia_id, usuario_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'TRASPASO', ?, ?)
            `, [movId, traspaso.empresa_id, traspaso.empresa_id, traspaso.almacen_destino_id,
                conceptoEntrada, item.producto_id, item.cantidad_recibida, item.costo_unitario,
                existAnterior, existNueva, traspasoId, usuario_id]);
            
            // Actualizar o insertar inventario destino
            if (invRow.length > 0) {
                await conn.query(
                    'UPDATE inventario SET stock = ?, ultimo_movimiento = NOW() WHERE almacen_id = ? AND producto_id = ?',
                    [existNueva, traspaso.almacen_destino_id, item.producto_id]
                );
            } else {
                const invId = 'INV' + Date.now() + Math.random().toString(36).substr(2, 5);
                await conn.query(`
                    INSERT INTO inventario (inventario_id, empresa_id, almacen_id, producto_id, stock, costo_promedio, ultimo_movimiento)
                    VALUES (?, ?, ?, ?, ?, ?, NOW())
                `, [invId, traspaso.empresa_id, traspaso.almacen_destino_id, item.producto_id, existNueva, item.costo_unitario]);
            }
        }
        
        // Actualizar estatus traspaso
        await conn.query(
            'UPDATE traspasos SET estatus = ?, fecha_recepcion = NOW() WHERE traspaso_id = ?',
            ['RECIBIDO', traspasoId]
        );
        
        await conn.commit();
        res.json({ success: true });
    } catch (e) {
        await conn.rollback();
        res.status(500).json({ success: false, error: e.message });
    } finally { conn.release(); }
});


// ==================== ALMACENES ====================

// GET - Listar almacenes por empresa
app.get('/api/almacenes/:empresaID', async (req, res) => {
    try {
        const [almacenes] = await db.query(`
            SELECT 
                a.almacen_id,
                a.codigo,
                a.nombre,
                a.tipo,
                a.es_punto_venta,
                a.permite_negativo,
                a.sucursal_id,
                s.nombre as sucursal_nombre,
                a.activo
            FROM almacenes a
            LEFT JOIN sucursales s ON a.sucursal_id = s.sucursal_id
            WHERE a.empresa_id = ? AND a.activo = 'Y'
            ORDER BY a.nombre
        `, [req.params.empresaID]);
        
        res.json({ success: true, almacenes });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// POST - Crear almacén
app.post('/api/almacenes', async (req, res) => {
    try {
        const { empresa_id, sucursal_id, codigo, nombre, tipo } = req.body;
        const almacen_id = 'ALM' + Date.now();
        
        await db.query(`
            INSERT INTO almacenes (almacen_id, empresa_id, sucursal_id, codigo, nombre, tipo, activo)
            VALUES (?, ?, ?, ?, ?, ?, 'Y')
        `, [almacen_id, empresa_id, sucursal_id, codigo || null, nombre, tipo || 'PRINCIPAL']);
        
        res.json({ success: true, almacen_id });
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==================== CONCEPTOS INVENTARIO ====================

app.get('/api/conceptos-inventario/:empresaID', async (req, res) => {
    try {
        const [conceptos] = await db.query(`
            SELECT concepto_id, codigo, nombre, tipo, afecta_costo
            FROM conceptos_inventario 
            WHERE empresa_id = ? AND activo = 'Y'
            ORDER BY tipo, nombre
        `, [req.params.empresaID]);
        
        res.json({ success: true, conceptos });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});
// ==================== START ====================

app.listen(PORT, () => console.log(`CAFI API puerto ${PORT}`));
