export abstract class KeyStore {
  abstract sign(hash: string): Promise<string>;

  abstract getPublicKey(): Promise<string>;
}
