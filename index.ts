import fs from "node:fs/promises";
import { extname } from "jsr:@std/path";
import { contentType } from "jsr:@std/media-types";
import { getCookies, setCookie } from "jsr:@std/http/cookie";
import crypto from "node:crypto";
import { Buffer } from "node:buffer";

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  TOKEN_ID,
  TOKEN_SECRET,
  PVE,
  COOKIE_SECRET,
} = Deno.env.toObject();

async function makeVnc(node: string, vmid: string, userId: string) {
  node = encodeURIComponent(node);
  vmid = encodeURIComponent(vmid);

  const config = await fetch(
    `${PVE}/api2/json/nodes/${node}/qemu/${vmid}/config`,
    {
      headers: {
        Authorization: `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
      },
    },
  ).then((r) => r.json());

  if (!config.data?.description?.includes(`discord=${userId}`)) {
    return null;
  }

  const vncproxy = await fetch(
    `${PVE}/api2/json/nodes/${node}/qemu/${vmid}/vncproxy`,
    {
      method: "POST",
      headers: {
        Authorization: `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ "websocket": 1, "generate-password": 1 }),
    },
  ).then((r) => r.json());

  return {
    password: vncproxy.data.password,
    url: `${PVE}/api2/json/nodes/${node}/qemu/${vmid}/vncwebsocket?port=${vncproxy.data.port}&vncticket=${encodeURIComponent(vncproxy.data.ticket)}`,
  };
}

function sign(payloadStr: string): string {
  const payload = Buffer.from(payloadStr);
  const hmac = crypto.createHmac("SHA256", Buffer.from(COOKIE_SECRET, "hex"));
  hmac.update(payload);
  const sig = hmac.digest("base64url");
  return `${sig}.${payload.toString("base64url")}`;
}

function verify(signed: string | undefined): string | null {
  if (!signed) return null;
  const [sig, payloadBuf] = signed.split(".");
  const payload = Buffer.from(payloadBuf, "base64url").toString();
  if (sign(payload) === signed) {
    return payload;
  }
  return null;
}

const INDEX_HTML = Deno.readTextFileSync("./index.html");
const STATIC: Record<string, { data: Uint8Array; contentType: string }> = {
  "/": {
    data: Deno.readFileSync("./index.html"),
    contentType: contentType(".html"),
  },
};
for await (const item of fs.glob("./noVNC/{core,vendor}/**/*.js")) {
  STATIC[`/${item}`] = {
    data: Deno.readFileSync(item),
    contentType: contentType(".js"),
  };
}

Deno.serve(async (req) => {
  const url = new URL(req.url);

  if (url.pathname === "/discord-callback") {
    const code = url.searchParams.get("code")!;
    const state = url.searchParams.get("state")!;

    const dauth = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      body: new URLSearchParams({
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT_URI,
      }),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }).then((r) => r.json());

    const user = await fetch("https://discord.com/api/v10/users/@me", {
      headers: {
        Authorization: `Bearer ${dauth.access_token}`,
      },
    }).then((r) => r.json());

    const res = new Response(null, {
      status: 307,
      headers: {
        location: verify(state)!,
      },
    });
    setCookie(res.headers, {
      name: "auth",
      value: sign(user.id),
      httpOnly: true,
      maxAge: 14400,
    });

    return res;
  }

  const cookies = getCookies(req.headers);
  const userId = verify(cookies.auth);

  if (!userId) {
    return Response.redirect(
      `https://discord.com/oauth2/authorize?client_id=${DISCORD_CLIENT_ID}&response_type=code&redirect_uri=${encodeURIComponent(DISCORD_REDIRECT_URI)}&scope=identify&state=${sign(req.url)}`,
      307,
    );
  }

  if (req.headers.get("upgrade")?.toLowerCase() === "websocket") {
    const result = await makeVnc(
      url.searchParams.get("node")!,
      url.searchParams.get("vmid")!,
      userId,
    );
    if (!result) {
      return new Response(null, { status: 401 });
    }

    const { socket, response } = Deno.upgradeWebSocket(req);

    const ws = new WebSocket(result.url, {
      headers: {
        Authorization: `PVEAPIToken=${TOKEN_ID}=${TOKEN_SECRET}`,
      },
    });

    ws.onclose = (e) => socket.close(e.code > 1000 ? 1000 : e.code, e.reason);
    ws.onmessage = (e) => socket.send(e.data);

    socket.onopen = () => socket.send(result.password);
    socket.onclose = (e) => ws.close(e.code > 1000 ? 1000 : e.code, e.reason);
    socket.onmessage = (e) => ws.send(e.data);

    return response;
  }

  const entry = STATIC[url.pathname];
  if (!entry) {
    return new Response("Not found", { status: 404 });
  }

  return new Response(entry.data, {
    headers: {
      "content-type": entry.contentType,
    },
  });
});
