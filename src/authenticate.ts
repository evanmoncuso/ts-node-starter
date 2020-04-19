import { Request, Response, NextFunction  } from 'express';
import { verify } from 'jsonwebtoken';

// TODO - add errors as exportables const

/**
 * @typedef AuthenticateTokenMiddlewareOptions
 * @type {object}
 * @property {string[]} roles - list of REQUIRED roles, if length 0, all roles are okay
 * @property {string[]} denyRoles - list of roles to deny access, if length 0, all roles are okay. Will override "roles"
 */
interface AuthTokenMiddlewareOptions {
  roles?: string[];
  denyRoles?: string[];
}


/**
 * Create a middleware function to authenticate requests with the included "options"
 * @param {AuthenticateTokenMiddlewareOptions} - options - restrictions on allowed permissions
 */
export function createTokenAuthMiddleware(options: AuthTokenMiddlewareOptions = {}) {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      // this will exist as it's checked in the app's init
      const ACCESS_SECRET = process.env.ACCESS_TOKEN_SECRET || '';
      const { authorization } = req.headers;

      if (!authorization) {
        res.status(401).send({
          error: 'No Authorization Header present'
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

      const { id, username, permissions }: AccessTokenPayload = v;
      const { roles, denyRoles } = options;

      if (!id || !username || !permissions) {
        res.status(401).send({
          error: 'Missing token parameters',
        });
        return
      }

      if (roles) {
        // @ts-ignore: roles will have length 1+
        if (roles.length && !permissions.includes(...roles)) {
          res.status(401).send({
            error: 'Incorrect Permissions'
          });
          return
        }
      }


      if (denyRoles) {
        // @ts-ignore: denyRoles will have length 1+
        if (denyRoles.length && permissions.includes(...denyRoles)) {
          res.status(401).send({
            error: 'Incorrect Permissions'
          });
          return
        }
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
        error: e
      })
    }
  }
}

export interface AccessTokenPayload {
  id?: string;
  username?: string;
  permissions?: string[]
}
