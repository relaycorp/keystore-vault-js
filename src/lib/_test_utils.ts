import { createHash } from 'crypto';

export function expectBuffersToEqual(
  buffer1: Buffer | ArrayBuffer,
  buffer2: Buffer | ArrayBuffer,
): void {
  if (buffer1 instanceof Buffer) {
    expect(buffer2).toBeInstanceOf(Buffer);
    expect(buffer1.equals(buffer2 as Buffer)).toBeTrue();
  } else {
    expect(buffer1).toBeInstanceOf(ArrayBuffer);
    expect(buffer2).toBeInstanceOf(ArrayBuffer);

    const actualBuffer1 = Buffer.from(buffer1);
    const actualBuffer2 = Buffer.from(buffer2);
    expect(actualBuffer1.equals(actualBuffer2)).toBeTrue();
  }
}

export function sha256Hex(plaintext: ArrayBuffer): string {
  return createHash('sha256').update(Buffer.from(plaintext)).digest('hex');
}

export async function expectPromiseToReject(
  promise: Promise<any>,
  expectedError: Error,
): Promise<void> {
  try {
    await promise;
  } catch (error) {
    expect(error).toHaveProperty('message', expectedError.message);
    expect(error).toBeInstanceOf(expectedError.constructor);
    return;
  }
  throw new Error(`Expected promise to throw error ${expectedError}`);
}
