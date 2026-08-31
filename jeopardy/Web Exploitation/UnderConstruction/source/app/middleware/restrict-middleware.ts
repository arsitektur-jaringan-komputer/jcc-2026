import { Middleware } from '@oak/oak';
import eta from '../lib/tpl-engine.ts';

export const restrictMiddleware: Middleware = async (ctx, next) => {
  const allowedIPs = ['localhost', '127.0.0.1'];
  const requestIP = ctx.request.ip;

  const invalid = allowedIPs.every((ip) => requestIP !== ip);

  if (invalid) {
    ctx.response.status = 200;
    ctx.response.body = eta.render('construction.html', {});
    return;
  }

  await next();
};
