import {
  MethodNotSupportedError,
  handleKeyringRequest,
} from '@metamask/keyring-api';
import type {
  OnKeyringRequestHandler,
  OnRpcRequestHandler,
} from '@metamask/snaps-types';
import { remove0x } from '@metamask/utils';

import { SimpleKeyring } from './keyring';
import { logger } from './logger';
import { InternalMethod, originPermissions } from './permissions';
import { getState } from './stateManagement';

let keyring: SimpleKeyring;

/**
 * Return the keyring instance. If it doesn't exist, create it.
 */
async function getKeyring(): Promise<SimpleKeyring> {
  if (!keyring) {
    const state = await getState();
    if (!keyring) {
      keyring = new SimpleKeyring(state);
    }
  }
  return keyring;
}

/**
 * Verify if the caller can call the requested method.
 *
 * @param origin - Caller origin.
 * @param method - Method being called.
 * @returns True if the caller is allowed to call the method, false otherwise.
 */
function hasPermission(origin: string, method: string): boolean {
  return originPermissions.get(origin)?.includes(method) ?? false;
}

  /**
   * Derive entropy which can be used as private key using the `snap_getEntropy`
   * JSON-RPC method. This method returns entropy which is specific to the snap,
   * so other snaps cannot replicate this entropy. This entropy is deterministic,
   * meaning that it will always be the same.
   *
   * The entropy is derived from the snap ID and the salt. The salt is used to
   * generate different entropy for different use cases. For example, in this
   * example we use the salt "Signing key" to generate entropy which can be used
   * as a private key.
   *
   * @param salt - The salt to use for the entropy derivation. Using a different
   * salt will result in completely different entropy being generated.
   * @returns The generated entropy, without the leading "0x".
   * @see https://docs.metamask.io/snaps/reference/rpc-api/#snap_getentropy
   */
  async function getEntropy(): Promise<string> {
    const entropy = await snap.request({
      method: 'snap_getEntropy',
      params: {
        version: 1
      },
    });

    return remove0x(entropy);
  }

export const onRpcRequest: OnRpcRequestHandler = async ({
  origin,
  request,
}) => {
  logger.debug(
    `RPC request (origin="${origin}"):`,
    JSON.stringify(request, undefined, 2),
  );

  // Check if origin is allowed to call method.
  if (!hasPermission(origin, request.method)) {
    throw new Error(
      `Origin '${origin}' is not allowed to call '${request.method}'`,
    );
  }

  // Handle custom methods.
  switch (request.method) {
    case InternalMethod.ToggleSyncApprovals: {
      return (await getKeyring()).toggleSyncApprovals();
    }

    case InternalMethod.IsSynchronousMode: {
      return (await getKeyring()).isSynchronousMode();
    }

    case InternalMethod.CreateAccountWithPrivateKey: {
      const entropy = await getEntropy();
      return (await getKeyring()).createAccount({ privateKey: entropy });
    }

    default: {
      throw new MethodNotSupportedError(request.method);
    }
  }
};

export const onKeyringRequest: OnKeyringRequestHandler = async ({
  origin,
  request,
}) => {
  logger.debug(
    `Keyring request (origin="${origin}"):`,
    JSON.stringify(request, undefined, 2),
  );

  // Check if origin is allowed to call method.
  if (!hasPermission(origin, request.method)) {
    throw new Error(
      `Origin '${origin}' is not allowed to call '${request.method}'`,
    );
  }

  // Handle keyring methods.
  return handleKeyringRequest(await getKeyring(), request);
};
