/* tslint:disable:no-let */
import {
  derSerializePrivateKey,
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
  PrivateKeyStoreError,
} from '@relaycorp/relaynet-core';
import axios, { AxiosRequestConfig } from 'axios';
import * as http from 'http';
import * as https from 'https';

import { expectBuffersToEqual, expectPromiseToReject, sha256Hex } from './_test_utils';
import { base64Encode } from './utils';
import { VaultPrivateKeyStore } from './vaultPrivateKeyStore';

describe('VaultPrivateKeyStore', () => {
  const mockAxiosCreate = jest.spyOn(axios, 'create');
  beforeEach(() => {
    mockAxiosCreate.mockReset();
  });
  afterAll(() => {
    mockAxiosCreate.mockRestore();
  });

  const stubVaultUrl = 'http://localhost:8200';
  const stubKvPath = 'pohttp-private-keys';
  const stubVaultToken = 'letmein';

  const sessionKeyPairId = '12345';
  let sessionKeyPair: CryptoKeyPair;
  let recipientKeyPair: CryptoKeyPair;
  beforeAll(async () => {
    sessionKeyPair = await generateECDHKeyPair();
    recipientKeyPair = await generateRSAKeyPair();
  });

  describe('constructor', () => {
    describe('Axios client', () => {
      const mockResponseInterceptorUse = jest.fn();
      beforeEach(() => {
        mockAxiosCreate.mockReturnValue({
          interceptors: {
            // @ts-ignore
            response: {
              use: mockResponseInterceptorUse,
            },
          },
        });
      });

      let axiosCreateCallOptions: AxiosRequestConfig;
      beforeEach(() => {
        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

        expect(mockAxiosCreate).toBeCalledTimes(1);
        axiosCreateCallOptions = mockAxiosCreate.mock.calls[0][0] as AxiosRequestConfig;
      });

      test('Keep alive should be used', () => {
        expect(axiosCreateCallOptions.httpsAgent).toBeInstanceOf(https.Agent);
        expect(axiosCreateCallOptions.httpsAgent).toHaveProperty('keepAlive', true);

        expect(axiosCreateCallOptions.httpAgent).toBeInstanceOf(http.Agent);
        expect(axiosCreateCallOptions.httpAgent).toHaveProperty('keepAlive', true);
      });

      test('A timeout of 3 seconds should be used', () => {
        expect(axiosCreateCallOptions).toHaveProperty('timeout', 3000);
      });

      test('Base URL should include Vault URL and KV path', () => {
        expect(axiosCreateCallOptions).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Base URL should be normalized', () => {
        mockAxiosCreate.mockClear();

        // tslint:disable-next-line:no-unused-expression
        new VaultPrivateKeyStore(`${stubVaultUrl}/`, stubVaultToken, `/${stubKvPath}/`);

        expect(mockAxiosCreate.mock.calls[0][0]).toHaveProperty(
          'baseURL',
          `${stubVaultUrl}/v1/${stubKvPath}/data`,
        );
      });

      test('Vault token should be included in the headers', () => {
        expect(axiosCreateCallOptions).toHaveProperty('headers.X-Vault-Token', stubVaultToken);
      });

      test('An error interceptor that removes sensitive data should be registered', async () => {
        const stubError = { message: 'Denied', sensitive: 's3cr3t' };

        expect(mockResponseInterceptorUse).toBeCalledTimes(1);

        const responseInterceptorCallArgs = mockResponseInterceptorUse.mock.calls[0];
        const errorInterceptor = responseInterceptorCallArgs[1];
        try {
          await errorInterceptor(stubError);
          fail('Expected interceptor to reject');
        } catch (error) {
          expect(error).toHaveProperty('message', stubError.message);
          expect(error).not.toHaveProperty('sensitive');
        }
      });
    });
  });

  describe('saveKey', () => {
    const mockAxiosClient = { post: jest.fn(), interceptors: { response: { use: jest.fn() } } };
    beforeEach(() => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 204 });

      // @ts-ignore
      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient);
    });

    test('Endpoint path should be the key id', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPairId);

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/${sessionKeyPairId}`);
    });

    test('Private key should be saved', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientKeyPair.publicKey,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
      );
    });

    test('Recipient key hash should be included in secret if present', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientKeyPair.publicKey,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      const recipientPublicKeyDigest = await sha256Hex(
        await derSerializePublicKey(recipientKeyPair.publicKey),
      );
      expect(postCallArgs[1]).toHaveProperty(
        'data.recipientPublicKeyDigest',
        recipientPublicKeyDigest,
      );
    });

    test('Recipient key hash should be missing from secret if unset', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSessionKey(sessionKeyPair.privateKey, sessionKeyPairId);

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[1]).not.toHaveProperty('data.recipientKeyHash');
    });

    test('Axios errors should be wrapped', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockRejectedValueOnce(new Error('Denied'));
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPairId,
          recipientKeyPair.publicKey,
        ),
        new PrivateKeyStoreError(`Failed to save session key ${sessionKeyPairId}: Denied`),
      );
    });

    test('A 200 OK response should be treated as success', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 200 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientKeyPair.publicKey,
      );
    });

    test('A 204 No Content response should be treated as success', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientKeyPair.publicKey,
      );
    });

    test('A non-200/204 response should raise an error', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 400 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.saveSessionKey(
          sessionKeyPair.privateKey,
          sessionKeyPairId,
          recipientKeyPair.publicKey,
        ),
        new PrivateKeyStoreError(
          `Failed to save session key ${sessionKeyPairId}: Vault returned a 400 response`,
        ),
      );
    });
  });

  describe('fetchKey', () => {
    const mockAxiosClient = { get: jest.fn(), interceptors: { response: { use: jest.fn() } } };
    beforeEach(async () => {
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockResolvedValueOnce({
        data: {
          data: {
            data: {
              privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
              recipientPublicKeyDigest: sha256Hex(
                await derSerializePublicKey(recipientKeyPair.publicKey),
              ),
              type: 'session',
            },
          },
        },
        status: 200,
      });

      // @ts-ignore
      mockAxiosCreate.mockReturnValueOnce(mockAxiosClient);
    });

    test('Private key should be returned decoded', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.fetchSessionKey(sessionKeyPairId, recipientKeyPair.publicKey);

      expectBuffersToEqual(
        await derSerializePrivateKey(privateKey),
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Endpoint path should be the key id', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.fetchSessionKey(sessionKeyPairId, recipientKeyPair.publicKey);

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/${sessionKeyPairId}`);
    });

    test('Retrieval should fail if recipient public key does not match secret', async () => {
      const differentRecipientKeyPair = await generateRSAKeyPair();
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyPairId, differentRecipientKeyPair.publicKey),
        new PrivateKeyStoreError(`Key ${sessionKeyPairId} is bound to another recipient`),
      );
    });

    test('Recipient public key should be ignored when session key is initial', async () => {
      // "Initial" means the key isn't bound to any specific session/recipient
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockResolvedValueOnce({
        data: {
          data: {
            data: {
              privateKey: base64Encode(await derSerializePrivateKey(sessionKeyPair.privateKey)),
              type: 'session',
            },
          },
        },
        status: 200,
      });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      const privateKey = await store.fetchSessionKey(sessionKeyPairId, recipientKeyPair.publicKey);

      expectBuffersToEqual(
        await derSerializePrivateKey(privateKey),
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Axios errors should be wrapped', async () => {
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockRejectedValueOnce(new Error('Denied'));
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyPairId, recipientKeyPair.publicKey),
        new PrivateKeyStoreError(`Failed to retrieve session key ${sessionKeyPairId}: Denied`),
      );
    });

    test('A non-200 response should raise an error', async () => {
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockResolvedValueOnce({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyPairId, recipientKeyPair.publicKey),
        new PrivateKeyStoreError(
          `Failed to retrieve session key ${sessionKeyPairId}: Vault returned a 204 response`,
        ),
      );
    });
  });
});
