import { DpopStorage } from './storage';
import * as dpopUtils from './utils';

export class Dpop {
  protected readonly storage: DpopStorage;
  private providedKeyPair?: dpopUtils.KeyPair;

  public constructor(clientId: string, keyPair?: dpopUtils.KeyPair) {
    this.storage = new DpopStorage(clientId);
    this.providedKeyPair = keyPair;
  }

  public getNonce(id?: string): Promise<string | undefined> {
    return this.storage.findNonce(id);
  }

  public setNonce(nonce: string, id?: string): Promise<void> {
    return this.storage.setNonce(nonce, id);
  }

  protected async getOrGenerateKeyPair(): Promise<dpopUtils.KeyPair> {
    if (this.providedKeyPair) {
      return this.providedKeyPair;
    }

    let keyPair = await this.storage.findKeyPair();

    if (!keyPair) {
      keyPair = await dpopUtils.generateKeyPair();
      await this.storage.setKeyPair(keyPair);
    }

    return keyPair;
  }

  public async generateProof(params: {
    url: string;
    method: string;
    nonce?: string;
    accessToken?: string;
  }): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return dpopUtils.generateProof({
      keyPair,
      ...params
    });
  }

  public async calculateThumbprint(): Promise<string> {
    const keyPair = await this.getOrGenerateKeyPair();

    return dpopUtils.calculateThumbprint(keyPair);
  }

  public async clear(): Promise<void> {
    await Promise.all([
      this.storage.clearNonces(),
      this.storage.clearKeyPairs()
    ]);
  }
}
