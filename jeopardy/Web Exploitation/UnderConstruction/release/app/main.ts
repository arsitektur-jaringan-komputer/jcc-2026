import { Application } from '@oak/oak';
import { Session } from 'oak_sessions';
import router from './router.ts';

const app = new Application();

app.use(Session.initMiddleware());
app.use(router.routes());
app.use(router.allowedMethods());

app.listen({
  port: 1337,
  hostname: '0.0.0.0',
});
