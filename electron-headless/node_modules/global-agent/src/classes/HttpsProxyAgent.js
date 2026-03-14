// @flow

import net from 'net';
import tls from 'tls';
import type {
  ConnectionCallbackType,
  ConnectionConfigurationType,
} from '../types';
import Agent from './Agent';

class HttpsProxyAgent extends Agent {
  // eslint-disable-next-line unicorn/prevent-abbreviations
  constructor (...args: *) {
    super(...args);

    this.protocol = 'https:';
    this.defaultPort = 443;
  }

  createConnection (configuration: ConnectionConfigurationType, callback: ConnectionCallbackType) {
    const socket = net.connect(
      configuration.proxy.port,
      configuration.proxy.hostname,
    );

    socket.on('error', (error) => {
      callback(error);
    });

    socket.once('data', () => {
      const secureSocket = tls.connect({
        ...configuration.tls,
        socket,
      });

      callback(null, secureSocket);
    });

    let connectMessage = '';

    connectMessage += 'CONNECT ' + configuration.host + ':' + configuration.port + ' HTTP/1.1\r\n';
    connectMessage += 'Host: ' + configuration.host + ':' + configuration.port + '\r\n';

    if (configuration.proxy.authorization) {
      connectMessage += 'Proxy-Authorization: Basic ' + Buffer.from(configuration.proxy.authorization).toString('base64') + '\r\n';
    }

    connectMessage += '\r\n';

    socket.write(connectMessage);
  }
}

export default HttpsProxyAgent;
