import { /* inject, */ BindingScope, injectable} from '@loopback/core';
import {repository} from '@loopback/repository';
import {Llaves} from '../config/llaves';
import {Usuario} from '../models';
import {UsuarioRepository} from '../repositories';
const generador = require('password-generator');
const cryptoJs = require('crypto-js');
const jwt = require('jsonwebtoken');


@injectable({scope: BindingScope.TRANSIENT})
export class AutenticacionService {
  constructor(
    @repository(UsuarioRepository)
    public usuarioRepository: UsuarioRepository
  ) { }

  /*
   * Add service methods here
   */

  GenerarContrasena() {
    let contrasena = generador(8, false);
    return contrasena;
  }

  Cifrarcontrasena(contrasena: string) {
    let contrasenaCifrada = cryptoJs.MD5(contrasena).toString();
    return contrasenaCifrada
  }

  IdentificarUsuario(usuario: string, contrasena: string, rol: string) {
    try {
      let p = this.usuarioRepository.findOne({where: {correo: usuario, contrasena: contrasena, rol: rol}});
      if (p) {
        return p;

      }

      return false;

    } catch {
      return false;
    }
  }

  GenerarTokenJWT(usuario: Usuario) {
    let token = jwt.sign({
      data: {
        id: usuario.id,
        correo: usuario.correo,
        nombre: usuario.nombre
      }
    },
      Llaves.claveJWT);
    return token;
  }

  ValidarTokenJWT(token: string) {
    try {
      let datos = jwt.verify(token, Llaves.claveJWT);
      return datos;
    } catch {
      return false;
    }
  }
}
