// @flow

import {
  serializeError,
} from 'serialize-error';
import {
  boolean,
} from 'boolean';
import Logger from '../Logger';
import type {
  AgentType,
  GetUrlProxyMethodType,
  IsProxyConfiguredMethodType,
  MustUrlUseProxyMethodType,
  ProtocolType,
} from '../types';

const log = Logger.child({
  namespace: 'Agent',
});

let requestId = 0;

class Agent {
  defaultPort: number;

  protocol: ProtocolType;

  fallbackAgent: AgentType;

  isProxyConfigured: IsProxyConfiguredMethodType;

  mustUrlUseProxy: MustUrlUseProxyMethodType;

  getUrlProxy: GetUrlProxyMethodType;

  socketConnectionTimeout: number;

  constructor (
    isProxyConfigured: IsProxyConfiguredMethodType,
    mustUrlUseProxy: MustUrlUseProxyMethodType,
    getUrlProxy: GetUrlProxyMethodType,
    fallbackAgent: AgentType,
    socketConnectionTimeout: number,
  ) {
    this.fallbackAgent = fallbackAgent;
    this.isProxyConfigured = isProxyConfigured;
    this.mustUrlUseProxy = mustUrlUseProxy;
    this.getUrlProxy = getUrlProxy;
    this.socketConnectionTimeout = socketConnectionTimeout;
  }

  addRequest (request: *, configuration: *) {
    let requestUrl;

    // It is possible that addRequest was constructed for a proxied request already, e.g.
    // "request" package does this when it detects that a proxy should be used
    // https://github.com/request/request/blob/212570b6971a732b8dd9f3c73354bcdda158a737/request.js#L402
    // https://gist.github.com/gajus/e2074cd3b747864ffeaabbd530d30218
    if (request.path.startsWith('http://') || request.path.startsWith('https://')) {
      requestUrl = request.path;
    } else {
      requestUrl = this.protocol + '//' + (configuration.hostname || configuration.host) + (configuration.port === 80 || configuration.port === 443 ? '' : ':' + configuration.port) + request.path;
    }

    if (!this.isProxyConfigured()) {
      log.trace({
        destination: requestUrl,
      }, 'not proxying request; GLOBAL_AGENT.HTTP_PROXY is not configured');

      // $FlowFixMe It appears that Flow is missing the method description.
      this.fallbackAgent.addRequest(request, configuration);

      return;
    }

    if (!this.mustUrlUseProxy(requestUrl)) {
      log.trace({
        destination: requestUrl,
      }, 'not proxying request; url matches GLOBAL_AGENT.NO_PROXY');

      // $FlowFixMe It appears that Flow is missing the method description.
      this.fallbackAgent.addRequest(request, configuration);

      return;
    }

    const currentRequestId = requestId++;

    const proxy = this.getUrlProxy(requestUrl);

    if (this.protocol === 'http:') {
      request.path = requestUrl;

      if (proxy.authorization) {
        request.setHeader('proxy-authorization', 'Basic ' + Buffer.from(proxy.authorization).toString('base64'));
      }
    }

    log.trace({
      destination: requestUrl,
      proxy: 'http://' + proxy.hostname + ':' + proxy.port,
      requestId: currentRequestId,
    }, 'proxying request');

    request.on('error', (error) => {
      log.error({
        error: serializeError(error),
      }, 'request error');
    });

    request.once('response', (response) => {
      log.trace({
        headers: response.headers,
        requestId: currentRequestId,
        statusCode: response.statusCode,
      }, 'proxying response');
    });

    request.shouldKeepAlive = false;

    const connectionConfiguration = {
      host: configuration.hostname || configuration.host,
      port: configuration.port || 80,
      proxy,
      tls: {},
    };

    // add optional tls options for https requests.
    // @see https://nodejs.org/docs/latest-v12.x/api/https.html#https_https_request_url_options_callback :
    // > The following additional options from tls.connect()
    // >   - https://nodejs.org/docs/latest-v12.x/api/tls.html#tls_tls_connect_options_callback -
    // > are also accepted:
    // >   ca, cert, ciphers, clientCertEngine, crl, dhparam, ecdhCurve, honorCipherOrder,
    // >   key, passphrase, pfx, rejectUnauthorized, secureOptions, secureProtocol, servername, sessionIdContext.
    if (this.protocol === 'https:') {
      connectionConfiguration.tls = {
        ca: configuration.ca,
        cert: configuration.cert,
        ciphers: configuration.ciphers,
        clientCertEngine: configuration.clientCertEngine,
        crl: configuration.crl,
        dhparam: configuration.dhparam,
        ecdhCurve: configuration.ecdhCurve,
        honorCipherOrder: configuration.honorCipherOrder,
        key: configuration.key,
        passphrase: configuration.passphrase,
        pfx: configuration.pfx,
        rejectUnauthorized: configuration.rejectUnauthorized,
        secureOptions: configuration.secureOptions,
        secureProtocol: configuration.secureProtocol,
        servername: configuration.servername || connectionConfiguration.host,
        sessionIdContext: configuration.sessionIdContext,
      };

      // This is not ideal because there is no way to override this setting using `tls` configuration if `NODE_TLS_REJECT_UNAUTHORIZED=0`.
      // However, popular HTTP clients (such as https://github.com/sindresorhus/got) come with pre-configured value for `rejectUnauthorized`,
      // which makes it impossible to override that value globally and respect `rejectUnauthorized` for specific requests only.
      //
      // eslint-disable-next-line no-process-env
      if (typeof process.env.NODE_TLS_REJECT_UNAUTHORIZED === 'string' && boolean(process.env.NODE_TLS_REJECT_UNAUTHORIZED) === false) {
        connectionConfiguration.tls.rejectUnauthorized = false;
      }
    }

    // $FlowFixMe It appears that Flow is missing the method description.
    this.createConnection(connectionConfiguration, (error, socket) => {
      log.trace({
        target: connectionConfiguration,
      }, 'connecting');

      // @see https://github.com/nodejs/node/issues/5757#issuecomment-305969057
      if (socket) {
        socket.setTimeout(this.socketConnectionTimeout, () => {
          socket.destroy();
        });

        socket.once('connect', () => {
          log.trace({
            target: connectionConfiguration,
          }, 'connected');

          socket.setTimeout(0);
        });

        socket.once('secureConnect', () => {
          log.trace({
            target: connectionConfiguration,
          }, 'connected (secure)');

          socket.setTimeout(0);
        });
      }

      if (error) {
        request.emit('error', error);
      } else {
        log.debug('created socket');

        socket.on('error', (socketError) => {
          log.error({
            error: serializeError(socketError),
          }, 'socket error');
        });

        request.onSocket(socket);
      }
    });
  }
}

export default Agent;
