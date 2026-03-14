// @flow

import net from 'net';
import type {
  ConnectionCallbackType,
  ConnectionConfigurationType,
} from '../types';
import Agent from './Agent';

class HttpProxyAgent extends Agent {
  // @see https://github.com/sindresorhus/eslint-plugin-unicorn/issues/169#issuecomment-486980290
  // eslint-disable-next-line unicorn/prevent-abbreviations
  constructor (...args: *) {
    super(...args);

    this.protocol = 'http:';
    this.defaultPort = 80;
  }

  createConnection (configuration: ConnectionConfigurationType, callback: ConnectionCallbackType) {
    const socket = net.connect(
      configuration.proxy.port,
      configuration.proxy.hostname,
    );

    callback(null, socket);
  }
}

export default HttpProxyAgent;
