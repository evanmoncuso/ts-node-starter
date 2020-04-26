import { Request, Response, NextFunction  } from 'express';
import { verify } from 'jsonwebtoken';

// TODO - add errors as exportables const

interface KVStore<T> {
  [ key: string ]: T;
}

function hasRoles(
  permissions: string[], 
  restrictions: KVStore<boolean>
): boolean {
  const c = permissions.filter((p) => restrictions[p]);
  return !!c.length;
}

/**
 * @typedef AuthenticateTokenMiddlewareOptions
 * @type {object}
 * @property {string[]} allowRoles - list of REQUIRED roles, if length 0, all roles are okay. If there are multiple roles it will access anyone with ANY of the roles
 * @property {string[]} denyRoles - list of roles to deny access, if length 0, all roles are okay. Will override "roles"
 */
interface AuthTokenMiddlewareOptions {
  allowRoles?: string[];
  denyRoles?: string[];
}


/**
 * Create a middleware function to authenticate requests with the included "options"
 * @param {AuthenticateTokenMiddlewareOptions} - options - restrictions on allowed permissions
 */
export function createTokenAuthMiddleware(options: AuthTokenMiddlewareOptions = {}) {
  const { allowRoles = [], denyRoles = [], } = options;

  const allowedRolesMap = allowRoles.reduce((o: KVStore<boolean>, r: string): KVStore<boolean> => {
    o[r] = true;
    return o;
  }, {});

  const denyRolesMap = denyRoles.reduce((o: KVStore<boolean>, r: string): KVStore<boolean> => {
    o[r] = true;
    return o;
  }, {});

  return (req: Request , res: Response, next: NextFunction): void => {
    try {
      // this will exist as it's checked in the app's init
      const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || '';
      const { authorization, } = req.headers;

      if (!authorization) {
        res.status(401).send({
          error: 'No Authorization Header present',
        });
        return
      } else if (authorization.slice(0, 7) !== 'Bearer ') {
        res.status(401).send({
          error: 'Authorization is not a "Bearer" token',
        });
        return
      }

      const token = authorization.slice(7);

      // verify token
      const v = verify(token, ACCESS_SECRET);
      if (typeof v === 'string') throw new Error('Unabled to decode token');

      const { id, username, permissions, }: AccessTokenPayload = v;

      if (!id || !username || !permissions) {
        res.status(401).send({ error: 'Missing token parameters', });
        return
      }

      // if user has one of the allowed permissions
      if (allowRoles.length && !hasRoles(permissions, allowedRolesMap)) {
        res.status(401).send({ error: 'Incorrect Permissions', });
        return
      }
      
      if (denyRoles.length &&hasRoles(permissions, denyRolesMap)) {
        res.status(401).send({ error: 'Incorrect Permissions', });
        return
      }

      // only attach decoded values if everything is okay
      res.locals = {
        id,
        username,
        permissions,
        ...res.locals,
      }

      next();
    } catch (e) {
      res.status(500).send({
        error: e,
      })
    }
  }
}

export interface AccessTokenPayload {
  id?: string;
  username?: string;
  permissions?: string[];
}
