# passman
Gestor de contraseñas con almacenaje en servidor que permita su acceso desde distintos clientes remotos.

#### Características básicas:
- ✅ Arquitectura cliente/servidor.
- ✅ Cada entrada incluirá, como mínimo, un identificador, un usuario y una contraseña.
- ✅ Mecanismo de autentificación seguro (gestión de contraseñas e identidades).
- ✅ Transporte de red seguro entre cliente y servidor (se puede emplear algún protocolo existente
como TLS o HTTPS).
- ✅ Cifrado de la base de datos de contraseñas en el servidor.

#### Características avanzadas:
- Generación de contraseñas aleatorias y por perfiles (longitud, grupos de caracteres, pronunciabilidad, etc.)
- ✅ Incorporación de datos adicionales (notas, números de tarjeta de crédito, etc.) en cada entrada.
- ✅ Optimización de la privacidad (conocimiento cero: el servidor sólo recibe datos cifrados por el cliente).
- Compartición de contraseñas con grupos de usuarios usando clave pública.
- Programar una extensión (https://developer.chrome.com/extensions/getstarted) de Google Chrome que se comunique con el servidor para buscar contraseñas guardadas y se puedan
usar fácilmente en el navegador.
