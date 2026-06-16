# Publicacion del POS con Cloudflare Tunnel y dominio fijo

Esta guia deja el POS listo para abrir desde un dominio o subdominio propio usando Cloudflare Tunnel.

## Archivos disponibles

- `pos_cloudflare.bat`: menu unico para POS, tunel temporal, dominio fijo, token y servicio.
- Los otros `.bat` de Cloudflare quedan como accesos compatibles al menu unico.

## 1) Requisitos

1. Tener cuenta de Cloudflare.
2. Tener el dominio delegado en Cloudflare.
3. Instalar `cloudflared` en Windows:

```bat
winget install Cloudflare.cloudflared
```

## 2) Crear el tunel en Cloudflare

1. Entrar a Cloudflare Dashboard.
2. Ir a `Zero Trust` o `Cloudflare One`.
3. Entrar a `Networks` / `Networking` > `Tunnels`.
4. Crear un tunel nuevo de tipo `Cloudflared`.
5. Elegir Windows como conector.
6. Copiar el comando que incluye el token.
7. Del comando, copiar solo el token que empieza por `eyJ...`.

## 3) Publicar el dominio o subdominio

En el tunel creado:

1. Ir a `Public Hostnames` o `Routes`.
2. Agregar hostname publico.
3. Subdomain: por ejemplo `pos`.
4. Domain: tu dominio, por ejemplo `tudominio.com`.
5. Service Type: `HTTP`.
6. URL: `127.0.0.1:5001`.
7. Guardar.

El resultado seria algo como:

`https://pos.tudominio.com`

## 4) Guardar el token en el proyecto

Ejecutar:

```bat
pos_cloudflare.bat
```

Elegir la opcion `3. Configurar token para dominio fijo` y pegar el token cuando lo pida.

El token se guarda en:

`instance\cloudflared_token.txt`

## 5) Probar manualmente

Ejecutar:

```bat
pos_cloudflare.bat
```

Elegir la opcion `4. Iniciar POS + dominio fijo`.

Se abren dos ventanas:

1. POS local en `http://127.0.0.1:5001`
2. Cloudflare Tunnel con dominio fijo

Luego abre el dominio configurado, por ejemplo:

`https://pos.tudominio.com`

## 6) Dejar el tunel como servicio de Windows

Para que el tunel inicie con Windows:

1. Abrir CMD como Administrador.
2. Ir a la carpeta del proyecto.
3. Ejecutar:

```bat
pos_cloudflare.bat
```

Elegir la opcion `5. Instalar tunel como servicio de Windows`.

Verificar estado:

```bat
sc query cloudflared
```

## 7) Operacion recomendada

Para prueba:

```bat
pos_cloudflare.bat
```

Elegir la opcion `4`.

Para uso 24/7:

1. Instalar el servicio de Cloudflare desde `pos_cloudflare.bat`, opcion `5`.
2. Mantener el POS ejecutandose con `iniciar_sistema.bat` o con el ejecutable cuando se compile.

## 8) Notas importantes

1. El token permite levantar el tunel, no lo compartas.
2. Si el token se filtra, rotalo desde Cloudflare.
3. El servicio local del POS debe estar disponible en `127.0.0.1:5001`.
4. El tunel temporal sigue disponible desde `pos_cloudflare.bat`, opcion `2`.
