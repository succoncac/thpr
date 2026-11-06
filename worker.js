/**
 * Cloudflare Worker Entry Point for TH10 Static Assets
 */
export default {
  async fetch(request, env) {
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }
    return new Response('TH10 Crypt is active. Assets binding initialized.', {
      status: 200,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
  },
};
