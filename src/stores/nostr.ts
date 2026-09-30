import { defineStore } from "pinia";
import { markRaw } from "vue";
import { useLocalStorage } from "@vueuse/core";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import {
  generateSecretKey,
  getEventHash,
  getPublicKey,
  nip04,
  nip19,
  nip44,
  verifyEvent,
} from "nostr-tools";
import type { EventTemplate } from "nostr-tools";
import type { RuntimeSubscription } from "nostr-pubsub";
import { nostrRuntime, publishEvent } from "src/js/nostrRuntime";
import {
  extensionSigner,
  privateSigner,
  remoteSigner,
} from "src/js/nostrSigner";
import type { WalletSigner } from "src/js/nostrSigner";
import { useWalletStore } from "./wallet";
import { useSettingsStore } from "./settings";
import { useReceiveTokensStore } from "./receiveTokensStore";
import {
  getEncodedTokenV4,
  PaymentRequestPayload,
  Token,
} from "@cashu/cashu-ts";
import { useTokensStore } from "./tokens";
import { notifyError, notifySuccess, notifyWarning } from "../js/notify";
import { useSendTokensStore } from "./sendTokensStore";
import { usePRStore } from "./payment-request";
import token from "../js/token";

type MintRecommendation = { url: string; count: number };
type NostrEventLog = { id: string; created_at: number };

export enum SignerType {
  NIP07 = "NIP07",
  NIP46 = "NIP46",
  PRIVATEKEY = "PRIVATEKEY",
  SEED = "SEED",
}

let initializing: Promise<void> | undefined;
const subscriptions = new Map<number, RuntimeSubscription>();

export const useNostrStore = defineStore("nostr", {
  state: () => ({
    pubkey: useLocalStorage<string>("cashu.ndk.pubkey", ""),
    relays: useSettingsStore().defaultNostrRelays,
    signerType: useLocalStorage<SignerType>(
      "cashu.ndk.signerType",
      localStorage.getItem("cashu.ndk.privateKeySignerPrivateKey")
        ? SignerType.PRIVATEKEY
        : SignerType.NIP07
    ),
    nip46Token: useLocalStorage<string>("cashu.ndk.nip46Token", ""),
    privateKeySignerPrivateKey: useLocalStorage<string>(
      "cashu.ndk.privateKeySignerPrivateKey",
      ""
    ),
    seedSignerPrivateKey: useLocalStorage<string>(
      "cashu.ndk.seedSignerPrivateKey",
      ""
    ),
    seedSignerPublicKey: useLocalStorage<string>(
      "cashu.ndk.seedSignerPublicKey",
      ""
    ),
    signer: null as WalletSigner | null,
    mintRecommendations: useLocalStorage<MintRecommendation[]>(
      "cashu.ndk.mintRecommendations",
      []
    ),
    initialized: false,
    lastEventTimestamp: useLocalStorage<number>(
      "cashu.ndk.lastEventTimestamp",
      0
    ),
    nip17EventIdsWeHaveSeen: useLocalStorage<NostrEventLog[]>(
      "cashu.ndk.nip17EventIdsWeHaveSeen",
      []
    ),
  }),
  getters: {
    seedSignerPrivateKeyNsec: (state) =>
      state.seedSignerPrivateKey
        ? nip19.nsecEncode(hexToBytes(state.seedSignerPrivateKey))
        : "",
    nprofile: (state) =>
      nip19.nprofileEncode({ pubkey: state.pubkey, relays: state.relays }),
    seedSignerNprofile: (state) =>
      nip19.nprofileEncode({
        pubkey: state.seedSignerPublicKey,
        relays: state.relays,
      }),
  },
  actions: {
    initSignerIfNotSet: async function () {
      if (!this.initialized) await this.initSigner();
    },
    initSigner: async function () {
      if (!initializing) {
        initializing = (async () => {
          if (this.signerType === SignerType.NIP07)
            await this.initNip07Signer();
          else if (this.signerType === SignerType.NIP46)
            await this.initNip46Signer();
          else if (this.signerType === SignerType.PRIVATEKEY)
            await this.initPrivateKeySigner();
          else await this.initWalletSeedPrivateKeySigner();
        })().finally(() => {
          initializing = undefined;
        });
      }
      await initializing;
    },
    setSigner: function (signer: WalletSigner, type: SignerType) {
      this.signer?.close?.();
      this.signer = markRaw(signer);
      this.pubkey = signer.pubkey;
      this.signerType = type;
      this.initialized = true;
    },
    signEvent: async function (event: EventTemplate) {
      await this.initSignerIfNotSet();
      if (!this.signer) throw new Error("Connect a signer first");
      return this.signer.signEvent(event);
    },
    checkNip07Signer: async function (): Promise<boolean> {
      try {
        return Boolean(await extensionSigner());
      } catch {
        return false;
      }
    },
    initNip07Signer: async function () {
      const signer = await extensionSigner();
      if (signer) this.setSigner(signer, SignerType.NIP07);
    },
    initNip46Signer: async function (nip46Token?: string) {
      const token =
        nip46Token ||
        this.nip46Token ||
        prompt("Enter your remote signer connection string");
      if (!token) return;
      const signer = await remoteSigner(token, this.relays, (url) =>
        window.open(url, "auth", "width=600,height=600")
      );
      this.nip46Token = token;
      this.setSigner(signer, SignerType.NIP46);
    },
    resetNip46Signer: async function () {
      this.nip46Token = "";
      await this.initWalletSeedPrivateKeySigner();
    },
    initPrivateKeySigner: async function (nsec?: string) {
      if (!nsec && !this.privateKeySignerPrivateKey)
        nsec = prompt("Enter your secret key") || undefined;
      let key: Uint8Array;
      if (nsec) {
        const decoded = nip19.decode(nsec);
        if (decoded.type !== "nsec") throw new Error("Invalid secret key");
        key = decoded.data;
      } else {
        if (!this.privateKeySignerPrivateKey) return;
        key = hexToBytes(this.privateKeySignerPrivateKey);
      }
      const signer = privateSigner(key);
      this.privateKeySignerPrivateKey = bytesToHex(key);
      this.setSigner(signer, SignerType.PRIVATEKEY);
    },
    resetPrivateKeySigner: async function () {
      this.privateKeySignerPrivateKey = "";
      await this.initWalletSeedPrivateKeySigner();
    },
    walletSeedGenerateKeyPair: async function () {
      const key = useWalletStore().seed.slice(0, 32);
      this.seedSignerPrivateKey = bytesToHex(key);
      this.seedSignerPublicKey = getPublicKey(key);
    },
    initWalletSeedPrivateKeySigner: async function () {
      await this.walletSeedGenerateKeyPair();
      this.setSigner(privateSigner(this.seedSignerPrivateKey), SignerType.SEED);
    },
    fetchEventsFromUser: async function () {
      const result = await nostrRuntime.query(
        [{ kinds: [1], authors: [this.pubkey] }],
        { relays: this.relays }
      );
      return new Set(result.events);
    },
    fetchMints: async function () {
      const { events } = await nostrRuntime.query(
        [{ kinds: [38000], limit: 2000 }],
        { relays: this.relays }
      );
      const counts = new Map<string, number>();
      for (const event of events) {
        const url = event.tags.find((tag: string[]) => tag[0] === "u")?.[1];
        if (
          event.tags.find((tag: string[]) => tag[0] === "k")?.[1] === "38172" &&
          url?.startsWith("https://")
        )
          counts.set(url, (counts.get(url) || 0) + 1);
      }
      this.mintRecommendations = Array.from(counts, ([url, count]) => ({
        url,
        count,
      })).sort((a, b) => b.count - a.count);
      return this.mintRecommendations;
    },
    sendNip04DirectMessage: async function (
      recipient: string,
      message: string
    ) {
      const key = generateSecretKey();
      try {
        await publishEvent(
          await privateSigner(key).signEvent({
            kind: 4,
            created_at: Math.floor(Date.now() / 1000),
            tags: [["p", recipient]],
            content: await nip04.encrypt(key, recipient, message),
          }),
          this.relays
        );
        notifySuccess("NIP-04 event published");
      } catch {
        notifyError("Could not publish NIP-04 event");
      }
    },
    subscribeToNip04DirectMessages: async function () {
      await this.walletSeedGenerateKeyPair();
      if (!this.lastEventTimestamp)
        this.lastEventTimestamp = Math.floor(Date.now() / 1000);
      subscriptions.get(4)?.close();
      subscriptions.set(
        4,
        nostrRuntime.subscribe(
          [
            {
              kinds: [4],
              "#p": [this.seedSignerPublicKey],
              since: this.lastEventTimestamp,
            },
          ],
          {
            onEvent: (event) => {
              void (async () => {
                const content = await nip04.decrypt(
                  hexToBytes(this.seedSignerPrivateKey),
                  event.pubkey,
                  event.content
                );
                this.lastEventTimestamp = Math.floor(Date.now() / 1000);
                await this.parseMessageForEcash(content);
              })().catch(() => undefined);
            },
          },
          { relays: this.relays, cache: "network-only", localEcho: false }
        )
      );
    },
    sendNip17DirectMessageToNprofile: async function (
      nprofile: string,
      message: string
    ) {
      const result = nip19.decode(nprofile);
      if (result.type !== "nprofile") throw new Error("Invalid recipient");
      await this.sendNip17DirectMessage(
        result.data.pubkey,
        message,
        result.data.relays
      );
    },
    randomTimeUpTo2DaysInThePast: function () {
      return Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 172800);
    },
    sendNip17DirectMessage: async function (
      recipient: string,
      message: string,
      relays?: string[]
    ) {
      await this.walletSeedGenerateKeyPair();
      const key = hexToBytes(this.seedSignerPrivateKey),
        randomKey = generateSecretKey();
      const rumor = {
        kind: 14,
        pubkey: this.seedSignerPublicKey,
        created_at: Math.floor(Date.now() / 1000),
        tags: [["p", recipient]],
        content: message,
      };
      const seal = await privateSigner(key).signEvent({
        kind: 13,
        created_at: this.randomTimeUpTo2DaysInThePast(),
        tags: [],
        content: nip44.v2.encrypt(
          JSON.stringify({ ...rumor, id: getEventHash(rumor) }),
          nip44.v2.utils.getConversationKey(key, recipient)
        ),
      });
      const wrap = await privateSigner(randomKey).signEvent({
        kind: 1059,
        created_at: this.randomTimeUpTo2DaysInThePast(),
        tags: [["p", recipient]],
        content: nip44.v2.encrypt(
          JSON.stringify(seal),
          nip44.v2.utils.getConversationKey(randomKey, recipient)
        ),
      });
      try {
        await publishEvent(wrap, relays ?? this.relays);
      } catch {
        notifyError("Could not publish NIP-17 event");
      }
    },
    subscribeToNip17DirectMessages: async function () {
      await this.walletSeedGenerateKeyPair();
      if (!this.lastEventTimestamp)
        this.lastEventTimestamp = Math.floor(Date.now() / 1000);
      subscriptions.get(1059)?.close();
      subscriptions.set(
        1059,
        nostrRuntime.subscribe(
          [
            {
              kinds: [1059],
              "#p": [this.seedSignerPublicKey],
              since: this.lastEventTimestamp - 172800,
            },
          ],
          {
            onEvent: (wrap) => {
              if (
                this.nip17EventIdsWeHaveSeen.some(
                  (event) => event.id === wrap.id
                )
              )
                return;
              try {
                const key = hexToBytes(this.seedSignerPrivateKey);
                const seal = JSON.parse(
                  nip44.v2.decrypt(
                    wrap.content,
                    nip44.v2.utils.getConversationKey(key, wrap.pubkey)
                  )
                );
                if (seal.kind !== 13 || !verifyEvent(seal)) return;
                const rumor = JSON.parse(
                  nip44.v2.decrypt(
                    seal.content,
                    nip44.v2.utils.getConversationKey(key, seal.pubkey)
                  )
                );
                if (
                  rumor.kind !== 14 ||
                  rumor.pubkey !== seal.pubkey ||
                  rumor.id !== getEventHash(rumor) ||
                  !rumor.tags.some(
                    (tag: string[]) =>
                      tag[0] === "p" && tag[1] === this.seedSignerPublicKey
                  )
                )
                  return;
                this.nip17EventIdsWeHaveSeen.push({
                  id: wrap.id,
                  created_at: wrap.created_at,
                });
                const cutoff =
                  Math.floor(Date.now() / 1000) - 10 * 24 * 60 * 60;
                this.nip17EventIdsWeHaveSeen =
                  this.nip17EventIdsWeHaveSeen.filter(
                    (event) => event.created_at > cutoff
                  );
                this.lastEventTimestamp = Math.floor(Date.now() / 1000);
                void this.parseMessageForEcash(rumor.content).catch(
                  () => undefined
                );
              } catch {
                /* Ignore malformed or undecryptable messages. */
              }
            },
          },
          { relays: this.relays, cache: "network-only", localEcho: false }
        )
      );
    },
    parseMessageForEcash: async function (message: string) {
      // first check if the message can be converted to a json and then to a PaymentRequestPayload
      try {
        const payload = JSON.parse(message) as PaymentRequestPayload;
        if (payload) {
          const receiveStore = useReceiveTokensStore();
          const prStore = usePRStore();
          const sendTokensStore = useSendTokensStore();
          const tokensStore = useTokensStore();
          const proofs = payload.proofs;
          const mint = payload.mint;
          const unit = payload.unit;
          const token = {
            proofs: proofs,
            mint: mint,
            unit: unit,
          } as Token;

          const tokenStr = getEncodedTokenV4(token);

          const tokenInHistory = tokensStore.tokenAlreadyInHistory(tokenStr);
          if (tokenInHistory && tokenInHistory.amount > 0) {
            console.log("### incoming token already in history");
            return;
          }
          await this.addPendingTokenToHistory(tokenStr, false);
          receiveStore.receiveData.tokensBase64 = tokenStr;
          sendTokensStore.showSendTokens = false;
          if (prStore.receivePaymentRequestsAutomatically) {
            const success = await receiveStore.receiveIfDecodes();
            if (success) {
              prStore.showPRDialog = false;
            } else {
              notifyWarning("Could not receive incoming payment");
            }
          } else {
            prStore.showPRDialog = false;
            receiveStore.showReceiveTokens = true;
          }
          return;
        }
      } catch (e) {
        // console.log("### parsing message for ecash failed");
        return;
      }

      console.log("### parsing message for ecash", message);
      const receiveStore = useReceiveTokensStore();
      const words = message.split(" ");
      const tokens = words.filter((word) => {
        return word.startsWith("cashuA") || word.startsWith("cashuB");
      });
      for (const tokenStr of tokens) {
        receiveStore.receiveData.tokensBase64 = tokenStr;
        receiveStore.showReceiveTokens = true;
        await this.addPendingTokenToHistory(tokenStr);
      }
    },
    addPendingTokenToHistory: function (tokenStr: string, verbose = true) {
      const receiveStore = useReceiveTokensStore();
      const tokensStore = useTokensStore();
      if (tokensStore.tokenAlreadyInHistory(tokenStr)) {
        notifySuccess("Ecash already in history");
        receiveStore.showReceiveTokens = false;
        return;
      }
      const decodedToken = token.decode(tokenStr);
      if (decodedToken == undefined) {
        throw Error("could not decode token");
      }
      // get amount from decodedToken.token.proofs[..].amount
      const amount = token
        .getProofs(decodedToken)
        .reduce((sum, el) => (sum += el.amount), 0);

      tokensStore.addPendingToken({
        amount: amount,
        token: tokenStr,
        mint: token.getMint(decodedToken),
        unit: token.getUnit(decodedToken),
      });
      receiveStore.showReceiveTokens = false;
      // show success notification
      if (verbose) {
        notifySuccess("Ecash added to history.");
      }
    },
  },
});
