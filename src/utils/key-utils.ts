import * as u8a from "uint8arrays";
import elliptic from "elliptic";
import sha3 from "js-sha3";
import { publicKeyConvert } from "secp256k1";

export function extractPublicKeyBytes(pk: VerificationMethod): Uint8Array {
    if (pk.publicKeyBase58) {
      return base58ToBytes(pk.publicKeyBase58);
    } else if (pk.publicKeyBase64) {
      return base64ToBytes(pk.publicKeyBase64);
    } else if (pk.publicKeyHex) {
      return hexToBytes(pk.publicKeyHex);
    } else if (
      pk.publicKeyJwk &&
      pk.publicKeyJwk.crv === "secp256k1" &&
      pk.publicKeyJwk.x &&
      pk.publicKeyJwk.y
    ) {
      const secp256k1 = new elliptic.ec("secp256k1");
      return hexToBytes(
        secp256k1
          .keyFromPublic({
            x: bytesToHex(base64ToBytes(pk.publicKeyJwk.x)),
            y: bytesToHex(base64ToBytes(pk.publicKeyJwk.y)),
          })
          .getPublic("hex")
      );
    }
    return new Uint8Array();
  }
  
  export function base64ToBytes(s: string): Uint8Array {
    const inputBase64Url = s
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
    return u8a.fromString(inputBase64Url, "base64url");
  }
  
  export function bytesToBase64(b: Uint8Array): string {
    return u8a.toString(b, "base64pad");
  }
  
  export function base58ToBytes(s: string): Uint8Array {
    return u8a.fromString(s, "base58btc");
  }
  
  export function bytesToBase58(b: Uint8Array): string {
    return u8a.toString(b, "base58btc");
  }
  export function hexToBytes(s: string): Uint8Array {
    const input = s.startsWith("0x") ? s.substring(2) : s;
    return u8a.fromString(input.toLowerCase(), "base16");
  }
  
  export function bytesToHex(b: Uint8Array): string {
    return u8a.toString(b, "base16");
  }
  
  export interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyBase58?: string;
    publicKeyBase64?: string;
    publicKeyJwk?: JsonWebKey;
    publicKeyHex?: string;
    publicKeyMultibase?: string;
    blockchainAccountId?: string;
    ethereumAddress?: string;
  }
  
  export function toEthereumAddress(hexPublicKey: string): string {
    const hashInput = u8a.fromString(hexPublicKey.slice(2), "base16");
    return `0x${u8a.toString(keccak(hashInput).slice(-20), "base16")}`;
  }
  
  export function keccak(data: Uint8Array): Uint8Array {
    return new Uint8Array(sha3.keccak_256.arrayBuffer(data));
  }
  
  export function getUncompressedPublicKey(publicKey: string): string {
    console.log("publicKey", publicKey);
    return _uint8ArrayToHex(publicKeyConvert(_hexToUnit8Array(publicKey), false));
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function _uint8ArrayToHex(arr: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    return Buffer.from(arr).toString("hex");
  }
  
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  export function _hexToUnit8Array(str: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    return new Uint8Array(Buffer.from(str, "hex"));
  }
  
  export function bytesToBase64url(b: Uint8Array): string {
    return u8a.toString(b, "base64url");
  }