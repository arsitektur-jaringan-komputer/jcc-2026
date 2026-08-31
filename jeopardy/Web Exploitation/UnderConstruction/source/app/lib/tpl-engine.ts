import { Eta } from '@bgub/eta';

const eta = new Eta({
  views: `${Deno.cwd()}/views/`,
  cache: false,
});

export default eta;
