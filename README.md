# Prueba de Ciberseguridad

Proyecto realizado en Python con el framework Flask.

Para correr el proyecto debe instalar Python, Pip y los siguientes paquetes:
* Flask
* pymongo
* requests
* werkzeug
* cryptography

Para permitir la modularizacion del proyecto, es necesario tener un archivo ```setup.py``` en la carpeta raiz en el cual estamos inicializando el servidor como un modulo de Python, por lo tanto, para correr el servidor debe ubicarse en la carpeta ```/app```\
```$- cd app```

Ejecutar el comando\
```$- flask --app routes run```


El proyecto cuenta con una base de datos no relacional MongoDB, la cual debe estar corriendo en el localhost:27017 al momento de correr el proyecto.

Para correr la base de datos localmente, visite el siguiente link \
https://www.mongodb.com/docs/mongodb-shell/install/#std-label-mdb-shell-install

## Creacion de usuario administrador

En el momento en el que esten, tanto el proyecto como la conexion a la base de datos corriendo, crear una base de datos llamada ```app_database``` y una coleccion ```users``` y crear un usuario administrador con los siguientes datos

```
{
    "user_id": "65bdf033-fb9f-443f-a60b-777efec15633",
    "username": "admin",
    "password":                 "sha256$4C3oG9lflwOHyT7i$54c79c8a5cf0d5c2227b347709002f23a8dd623d2c87738a6c453a13d9896a6b",
    "isAdmin": true
}
```

Desde el front-end del proyecto las credenciales de entrada serian las siguientes:
```
    username: admin
    password: $admin
```
