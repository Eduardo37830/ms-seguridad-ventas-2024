import {
  AuthenticationBindings,
  AuthenticationMetadata,
  AuthenticationStrategy,
} from '@loopback/authentication';
import {inject, service} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors, Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import {RolMenuRepository} from '../repositories';
import {SeguridadUsuarioService} from '../services';

export class AuthStrategy implements AuthenticationStrategy {
  name: string = 'auth';

  constructor(
    @service(SeguridadUsuarioService)
    private servicioSeguridad: SeguridadUsuarioService,
    @inject(AuthenticationBindings.METADATA)
    private metadata: AuthenticationMetadata[] /* El metadata siempre es un arreglo */,
    @repository(RolMenuRepository)
    private repositorioRolMenu: RolMenuRepository,
  ) {}

  /**
   * Autenticacion de un usuario frente a una accion en una base de datos
   * @param request la solicitud con el token
   * @returns el perfil del usuario o undefined cuando no tiene permiso o http error.
   */

  async authenticate(request: Request): Promise<UserProfile | undefined> {
    let token = parseBearerToken(request);
    if (token) {
      let idRol = this.servicioSeguridad.obtenerRolDesdeToken(token);
      let idMenu: string = this.metadata[0].options![0];
      let accion: string = this.metadata[0].options![1];

      let permiso = await this.repositorioRolMenu.findOne({
        where: {
          rolId: idRol,
          menuId: idMenu,
        },
      });
      let continuar: boolean = false;
      if (permiso) {
        switch (accion) {
          case 'guardar':
            continuar = permiso.guardar;
            break;
          case 'editar':
            continuar = permiso.editar;
            break;
          case 'listar':
            continuar = permiso.listar;
            break;
          case 'eliminar':
            continuar = permiso.eliminar;
            break;
          case 'descargar':
            continuar = permiso.descargar;
            break;
          default:
            throw new HttpErrors[401](
              'No es posible ejecutar la acción porque no existe',
            );
            break;
        }
      } else {
        throw new HttpErrors[401](
          'No es posible ejecutar la accion por falta de permisos',
        );
      }
      if (continuar) {
        let perfil: UserProfile = Object.assign({
          permitido: 'OK',
        });
        return perfil;
      } else {
        return undefined;
      }
    }
    throw new HttpErrors[401](
      'No es posible ejecutar la accion por falta de un token',
    );
  }
}
