import { createNostrRuntime, NostrEvent } from "nostr-pubsub";

// Signers, payment messages and wallet connections share relay sockets. Every
// operation supplies its relay scope, without changing the other subscriptions.
export const nostrRuntime = createNostrRuntime({ relays: [] });

export async function publishEvent(event: NostrEvent, relays: string[]) {
  const result = await nostrRuntime.publish(event, {
    relays,
    requireAck: true,
    queue: false,
    localEcho: false,
  });
  if (!result.remoteAccepted)
    throw new Error("No message server accepted the event");
}
