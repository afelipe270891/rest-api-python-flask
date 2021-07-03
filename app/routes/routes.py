from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from models.models import Usuario, Pelicula
from schema.schemas import pelicula_schema, peliculas_schema
from database import db
import bcrypt

blue_print = Blueprint('app', __name__)

#Ruta de inicio
@blue_print.route('/', methods=['GET'])
def inicio():
    return jsonify(respuesta = 'Rest Api con Python, Flask y Mysql')

#Ruta de registro de usuario
@blue_print.route('/auth/registrar', methods=['POST'])
def registrar_usuario():
    try:
        #obtener el usuario
        usuario = request.json.get('usuario')
        clave = request.json.get('clave')

        if not usuario or not clave:
            return jsonify(respuesta='Campos Requeridos'), 400

        #Consultar la DB
        existe_usuario = Usuario.query.filter_by(usuario=usuario).first()
        
        if existe_usuario:
            return jsonify(respuesta= 'Usuario ya existe'), 400
        
        #Encriptar clave de usuario
        clave_encriptada = bcrypt.hashpw(clave.encode('utf8'), bcrypt.gensalt())

        #creamos el Modelo a guardar DB
        nuevo_usuario = Usuario(usuario, clave_encriptada)

        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify(respuesta='Usuario creado correctamente'),201

    except Exception:
        return jsonify(respuesta = 'Error en Peticion'), 500

#Ruta para iniciar sesion
@blue_print.route('/auth/login', methods=['POST'])
def iniciar_sesion():
    try:
        #obtener el usuario
        usuario = request.json.get('usuario')
        clave = request.json.get('clave')

        if not usuario or not clave:
            return jsonify(respuesta='Campos Requeridos'), 400

        #Consultar la DB
        existe_usuario = Usuario.query.filter_by(usuario=usuario).first()

        if not existe_usuario:
            return jsonify(respuesta='Usuario no existe'), 404
        
        es_clave_valida = bcrypt.checkpw(clave.encode('utf-8'), existe_usuario.clave.encode('utf-8'))

        #Validamos que sean iguales las claves
        if es_clave_valida:
            access_token = create_access_token(identity=usuario)
            return jsonify(access_token=access_token), 200
        return jsonify(respuesta='Usuario o Clave incorrecta'), 404        
    except Exception:
        return jsonify(respuesta = 'Error al Iniciar Sesión'), 500

#RUTAS PROTEGIDAS POR JWT

#Ruta - Crear Pelicula
@blue_print.route('/api/peliculas', methods=['POST'])
@jwt_required()
def crear_pelicula():
    try:
        nombre = request.json['nombre']
        estreno = request.json['estreno']
        director = request.json['director']
        reparto = request.json['reparto']
        genero = request.json['genero']
        sinopsis = request.json['sinopsis']

        nueva_pelicula = Pelicula(nombre, estreno, director, reparto, genero, sinopsis)
        db.session.add(nueva_pelicula)
        db.session.commit()
        return jsonify(respuesta='Pelicula creada correctamente'), 201

    except Exception:
        return jsonify(respuesta = 'Error al crear la pelicula'), 500

#Ruta - Obtener Peliculas
@blue_print.route('/api/peliculas', methods=['GET'])
@jwt_required()
def obtener_peliculas():
    try:
        peliculas = Pelicula.query.all()
        respuesta = peliculas_schema.dump(peliculas)
        return peliculas_schema.jsonify(respuesta), 200

    except Exception:
        return jsonify(respuesta = 'Error al buscar las peliculas'), 500

#Ruta - Obtener Pelicula por Id
@blue_print.route('/api/peliculas/<int:id>', methods=['GET'])
@jwt_required()
def obtener_pelicula_id(id):
    try:
        pelicula = Pelicula.query.get(id)
        return pelicula_schema.jsonify(pelicula), 200

    except Exception:
        return jsonify(respuesta = 'Error al bscar la pelicula por id'), 500

#Ruta - Actualizar Pelicula
@blue_print.route('/api/peliculas/<int:id>', methods=['PUT'])
@jwt_required()
def actualizar_pelicula(id):
    try:
        pelicula = Pelicula.query.get(id)
        if not pelicula:
            return jsonify(respuesta= 'Pelicula no encontrada'), 404

        pelicula.nombre = request.json['nombre']
        pelicula.estreno = request.json['estreno']
        pelicula.director = request.json['director']
        pelicula.reparto = request.json['reparto']
        pelicula.genero = request.json['genero']
        pelicula.sinopsis = request.json['sinopsis']

        db.session.commit()
        return jsonify(respuesta='Pelicula actualizada correctamente'), 200

    except Exception:
        return jsonify(respuesta = 'Error al actualizar la pelicula'), 500

#Ruta - Eliminar Pelicula por Id
@blue_print.route('/api/peliculas/<int:id>', methods=['DELETE'])
@jwt_required()
def eliminar_pelicula_id(id):
    try:
        pelicula = Pelicula.query.get(id)
        if not pelicula:
            return jsonify(respuesta= 'Pelicula no encontrada'), 404

        db.session.delete(pelicula)
        db.session.commit()
        return jsonify(respuesta='Pelicula eliminada correctamente'), 200

    except Exception:
        return jsonify(respuesta = 'Error al eliminar la pelicula por id'), 500