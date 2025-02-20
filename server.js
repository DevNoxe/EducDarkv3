const express = require('express');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken'); // Necesario para crear y verificar el token
const prisma = new PrismaClient();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para habilitar CORS y servir archivos estáticos
app.use(cors());
app.use(express.static('public'));
app.use(express.json());

// Intentar conexión a la base de datos y registrar si ocurre un error
prisma.$connect()
  .then(() => {
    console.log('Conexión a MongoDB exitosa');
  })
  .catch((e) => {
    console.error('Error al conectar con la base de datos', e);
  });

// Ruta para el registro de usuarios
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Verificar si el usuario ya existe
  const existingUser = await prisma.user.findUnique({
    where: { username }
  });

  if (existingUser) {
    return res.status(400).json({ error: 'El nombre de usuario ya existe.' });
  }

  // Cifrar la contraseña antes de guardarla
  const hashedPassword = await bcrypt.hash(password, 10);

  // Crear el nuevo usuario en la base de datos
  const newUser = await prisma.user.create({
    data: {
      username: username,
      password: hashedPassword
    }
  });

  res.status(201).json({ message: `Usuario ${newUser.username} registrado exitosamente` });
});

// Ruta para el login de usuarios
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Buscar el usuario en la base de datos
  const user = await prisma.user.findUnique({ where: { username } });
  if (!user) {
    return res.status(400).json({ error: 'Usuario no encontrado' });
  }

  // Verificar la contraseña comparando la contraseña cifrada
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: 'Contraseña incorrecta' });
  }

  // Crear un token con JWT (en este caso el token es solo un ejemplo)
  const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });

  res.json({
    message: 'Login exitoso',
    user: {
      username: user.username,
      nombre: user.nombre, // Devuelve los datos del usuario
    },
    token
  });
});

// Ruta para buscar correo (requiere que el usuario esté logueado)
app.post('/buscar-correo', async (req, res) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Obtener token del encabezado

  if (!token) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  try {
    // Verificar el token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    
    // Si el token es válido, proceder con la búsqueda
    const { correoEduca } = req.body;
    const user = await prisma.user.findUnique({
      where: { correoEduca }
    });

    if (!user) {
      return res.status(400).json({ error: 'Correo no encontrado' });
    }

    res.json({ message: 'Correo encontrado', user });
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
});

// Iniciar el servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
