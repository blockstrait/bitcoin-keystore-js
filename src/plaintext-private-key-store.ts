import { KeyStore } from './key-store';

/* eslint @typescript-eslint/no-require-imports: "off" */
const bsv = require('bsv');

export interface PlaintextPrivateKeyStoreParams {
  privateKeyWif: string;
}

export class PlaintextPrivateKeyStore extends KeyStore {
  private privateKey;

  constructor(params: PlaintextPrivateKeyStoreParams) {
    super();

    const { privateKeyWif } = params;

    if (privateKeyWif === undefined) {
      throw new Error('`privateKeyWif` parameter is mandatory');
    }

    try {
      this.privateKey = bsv.PrivateKey.fromWIF(privateKeyWif);
    } catch (error) {
      throw new Error('Invalid private key value');
    }
  }

  async getPublicKey(): Promise<string> {
    return this.privateKey.publicKey.toString();
  }

  async sign(hash: string): Promise<string> {
    const ECDSA = bsv.crypto.ECDSA;

    const signature = ECDSA.signWithCalcI(hash, this.privateKey);

    return signature.toString();
  }
}
