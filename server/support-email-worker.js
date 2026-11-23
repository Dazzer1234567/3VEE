// Cloudflare Email Worker for support@3vee.app
//
// Cloudflare Email Routing hands every email sent to support@3vee.app to this Worker. It passes the raw
// email to the 3vee.app server, which stores it in the support inbox (admin page) and notifies the owner.
// If the server can't be reached or refuses it, the email is forwarded to FALLBACK_TO instead, so
// nothing is lost.
//
// Settings (Worker > Settings > Variables and Secrets):
//   INBOUND_URL     https://3vee.app/api/inbound-email
//   INBOUND_SECRET  (secret) the same value as INBOUND_SECRET in /etc/masterdaw-beta.env on the server
//   FALLBACK_TO     a verified Email Routing destination address (e.g. the owner's Gmail)

export default {
  async email(message, env, ctx) {
    const raw = await new Response(message.raw).arrayBuffer();
    try {
      const res = await fetch(env.INBOUND_URL, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${env.INBOUND_SECRET}`,
          "Content-Type": "message/rfc822",
          "X-Envelope-From": message.from,
          "X-Envelope-To": message.to,
        },
        body: raw,
      });
      if (res.ok) return;
      console.log(`server refused the email: HTTP ${res.status}`);
    } catch (err) {
      console.log(`server unreachable: ${err}`);
    }
    await message.forward(env.FALLBACK_TO);
  },
};
