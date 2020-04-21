/* tslint:disable:no-let */

import {
  Certificate,
  derSerializePrivateKey,
  derSerializePublicKey,
  generateECDHKeyPair,
  generateRSAKeyPair,
  issueEndpointCertificate,
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

  const TOMORROW = new Date();
  TOMORROW.setDate(TOMORROW.getDate() + 1);

  const sessionKeyPairId = Buffer.from([9, 7, 5, 3, 1]);
  let sessionKeyPair: CryptoKeyPair;
  let senderPrivateKey: CryptoKey;
  let senderCertificate: Certificate;
  let recipientKeyPair: CryptoKeyPair;
  let recipientCertificate: Certificate;
  beforeAll(async () => {
    sessionKeyPair = await generateECDHKeyPair();

    const senderKeyPair = await generateRSAKeyPair();
    senderPrivateKey = senderKeyPair.privateKey;
    senderCertificate = await issueEndpointCertificate({
      issuerPrivateKey: senderKeyPair.privateKey,
      subjectPublicKey: senderKeyPair.publicKey,
      validityEndDate: TOMORROW,
    });

    recipientKeyPair = await generateRSAKeyPair();
    recipientCertificate = await issueEndpointCertificate({
      issuerPrivateKey: recipientKeyPair.privateKey,
      subjectPublicKey: recipientKeyPair.publicKey,
      validityEndDate: TOMORROW,
    });
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
      await store.saveSubsequentSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientCertificate,
      );

      expect(mockAxiosClient.post).toBeCalledTimes(1);
      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[0]).toEqual(`/${sessionKeyPairId.toString('hex')}`);
    });

    test('Private key and type should be saved', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveNodeKey(senderPrivateKey, senderCertificate);

      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[1]).toHaveProperty(
        'data.privateKey',
        base64Encode(await derSerializePrivateKey(senderPrivateKey)),
      );
      expect(postCallArgs[1]).toHaveProperty('data.type', 'node');
    });

    test('Recipient public key digest should be saved if key is bound', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveSubsequentSessionKey(
        sessionKeyPair.privateKey,
        sessionKeyPairId,
        recipientCertificate,
      );

      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[1]).toHaveProperty(
        'data.recipientPublicKeyDigest',
        sha256Hex(await derSerializePublicKey(await recipientCertificate.getPublicKey())),
      );
    });

    test('Certificate should be saved if key is unbound', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);
      await store.saveNodeKey(senderPrivateKey, senderCertificate);

      const postCallArgs = mockAxiosClient.post.mock.calls[0];
      expect(postCallArgs[1]).toHaveProperty(
        'data.certificate',
        base64Encode(await senderCertificate.serialize()),
      );
    });

    test('Axios errors should be wrapped', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockRejectedValueOnce(new Error('Denied'));
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.saveNodeKey(senderPrivateKey, senderCertificate),
        new PrivateKeyStoreError(`Failed to save key: Denied`),
      );
    });

    test('A 200 OK response should be treated as success', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 200 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveNodeKey(senderPrivateKey, senderCertificate);
    });

    test('A 204 No Content response should be treated as success', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.saveNodeKey(senderPrivateKey, senderCertificate);
    });

    test('A non-200/204 response should raise an error', async () => {
      mockAxiosClient.post.mockReset();
      mockAxiosClient.post.mockResolvedValueOnce({ status: 400 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.saveNodeKey(senderPrivateKey, senderCertificate),
        new PrivateKeyStoreError(`Failed to save key: Vault returned a 400 response`),
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

      const privateKey = await store.fetchSessionKey(sessionKeyPairId, recipientCertificate);

      expectBuffersToEqual(
        await derSerializePrivateKey(privateKey),
        await derSerializePrivateKey(sessionKeyPair.privateKey),
      );
    });

    test('Endpoint path should be the key id', async () => {
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await store.fetchSessionKey(sessionKeyPairId, recipientCertificate);

      expect(mockAxiosClient.get).toBeCalledTimes(1);
      const getCallArgs = mockAxiosClient.get.mock.calls[0];
      expect(getCallArgs[0]).toEqual(`/${sessionKeyPairId.toString('hex')}`);
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

      const privateKey = await store.fetchSessionKey(sessionKeyPairId, recipientCertificate);

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
        store.fetchSessionKey(sessionKeyPairId, recipientCertificate),
        new PrivateKeyStoreError(`Failed to retrieve key: Denied`),
      );
    });

    test('A non-200 response should raise an error', async () => {
      mockAxiosClient.get.mockReset();
      mockAxiosClient.get.mockResolvedValueOnce({ status: 204 });
      const store = new VaultPrivateKeyStore(stubVaultUrl, stubVaultToken, stubKvPath);

      await expectPromiseToReject(
        store.fetchSessionKey(sessionKeyPairId, recipientCertificate),
        new PrivateKeyStoreError(`Failed to retrieve key: Vault returned a 204 response`),
      );
    });
  });
});
