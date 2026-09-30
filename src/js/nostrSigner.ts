import {
  Event,
  EventTemplate,
  finalizeEvent,
  generateSecretKey,
  getEventHash,
  getPublicKey,
  nip04,
  nip19,
  verifyEvent,
} from "nostr-tools";
import { hexToBytes } from "@noble/hashes/utils";
import { nostrRuntime, publishEvent } from "src/js/nostrRuntime";

export interface WalletSigner {
  pubkey: string;
  signEvent(event: EventTemplate): Promise<Event>;
  close?(): void;
}

export function privateSigner(key: string | Uint8Array): WalletSigner {
  const secret = typeof key === "string" ? hexToBytes(key) : key;
  return {
    pubkey: getPublicKey(secret),
    signEvent: async (event) => finalizeEvent(event, secret),
  };
}

function checkedSignature(
  value: Event,
  template: EventTemplate,
  pubkey: string
): Event {
  const event = { ...template, pubkey, id: value.id, sig: value.sig };
  if (event.id !== getEventHash(event) || !verifyEvent(event)) {
    throw new Error("Signer returned an invalid signature");
  }
  return event;
}

export async function extensionSigner(): Promise<WalletSigner | undefined> {
  const extension = (
    window as Window & {
      nostr?: {
        getPublicKey(): Promise<string>;
        signEvent(event: EventTemplate & { pubkey: string }): Promise<Event>;
      };
    }
  ).nostr;
  if (!extension) return;
  const pubkey = await extension.getPublicKey();
  if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error("Invalid signer user ID");
  return {
    pubkey,
    signEvent: async (event) => {
      // The extension can mutate its argument; retain the requested payload.
      const expected = { ...event, tags: event.tags.map((tag) => [...tag]) };
      return checkedSignature(
        await extension.signEvent({
          ...expected,
          tags: expected.tags.map((tag) => [...tag]),
          pubkey,
        }),
        expected,
        pubkey
      );
    },
  };
}

const REQUEST_TIMEOUT_MS = 60_000;

/** Preserve the raw/npub[#token] and NIP05 formats stored by the legacy wallet. */
export async function remoteSigner(
  token: string,
  relays: string[],
  onAuthUrl: (url: string) => void
): Promise<WalletSigner> {
  const [identifier, secret] = token.split("#");
  let pubkey = identifier;
  if (identifier.startsWith("npub")) {
    const decoded = nip19.decode(identifier);
    if (decoded.type !== "npub") throw new Error("Invalid signer user ID");
    pubkey = decoded.data;
  } else if (!/^[0-9a-f]{64}$/.test(identifier)) {
    const match = identifier.match(
      /^(?:([a-z0-9_.+-]+)@)?([a-z0-9.-]+\.[a-z]{2,})$/i
    );
    if (!match) throw new Error("Invalid remote signer address");
    const name = (match[1] || "_").toLowerCase();
    const response = await fetch(
      `https://${match[2]}/.well-known/nostr.json?name=${encodeURIComponent(
        name
      )}`,
      {
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }
    );
    if (!response.ok) throw new Error("Remote signer lookup failed");
    const profile = await response.json();
    pubkey = profile.names?.[name];
    if (Array.isArray(profile.nip46?.[pubkey])) relays = profile.nip46[pubkey];
  }
  if (!/^[0-9a-f]{64}$/.test(pubkey)) throw new Error("Invalid signer user ID");
  const localKey = generateSecretKey(),
    local = privateSigner(localKey);
  const pending = new Map<
    string,
    {
      resolve(value: string): void;
      reject(error: Error): void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  let closed = false;
  let readyResolve: () => void, readyReject: (error: Error) => void;
  const ready = new Promise<void>((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const subscription = nostrRuntime.subscribe(
    [{ kinds: [24133, 24134], authors: [pubkey], "#p": [local.pubkey] }],
    {
      onEose: (status) => {
        if (status.complete) readyResolve();
        else readyReject(new Error("Remote signer connection unavailable"));
      },
      onEvent: (event) => {
        void (async () => {
          const response = JSON.parse(
            await nip04.decrypt(localKey, pubkey, event.content)
          );
          const request = pending.get(response.id);
          if (!request) return;
          if (response.result === "auth_url") {
            const url = new URL(response.error);
            if (url.protocol === "https:" || url.protocol === "http:")
              onAuthUrl(url.href);
            return;
          }
          pending.delete(response.id);
          clearTimeout(request.timer);
          if (response.error) request.reject(new Error(String(response.error)));
          else if (typeof response.result !== "string")
            request.reject(new Error("Invalid signer response"));
          else request.resolve(response.result);
        })().catch(() => undefined);
      },
    },
    {
      relays,
      cache: "network-only",
      localEcho: false,
      deadline: Date.now() + REQUEST_TIMEOUT_MS,
    }
  );
  function close() {
    if (closed) return;
    closed = true;
    subscription.close();
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error("Signer connection closed"));
    }
    pending.clear();
  }
  function request(method: string, params: string[]): Promise<string> {
    if (closed) return Promise.reject(new Error("Signer connection closed"));
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error("Remote signer did not respond"));
      }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      void (async () => {
        const content = await nip04.encrypt(
          localKey,
          pubkey,
          JSON.stringify({ id, method, params })
        );
        await publishEvent(
          await local.signEvent({
            kind: 24133,
            created_at: Math.floor(Date.now() / 1000),
            content,
            tags: [["p", pubkey]],
          }),
          relays
        );
      })().catch((error) => {
        if (!pending.delete(id)) return;
        clearTimeout(timer);
        reject(error);
      });
    });
  }
  try {
    await ready;
    if (
      (await request("connect", secret ? [pubkey, secret] : [pubkey])) !== "ack"
    )
      throw new Error("Remote signer rejected connection");
    return {
      pubkey,
      signEvent: async (event) =>
        checkedSignature(
          JSON.parse(
            await request("sign_event", [JSON.stringify({ ...event, pubkey })])
          ),
          event,
          pubkey
        ),
      close,
    };
  } catch (error) {
    close();
    throw error;
  }
}
