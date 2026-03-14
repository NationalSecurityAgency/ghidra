// @flow

import {
  parse as parseUrl,
} from 'url';
import {
  UnexpectedStateError,
} from '../errors';

export default (url: string) => {
  const urlTokens = parseUrl(url);

  if (urlTokens.query !== null) {
    throw new UnexpectedStateError('Unsupported `GLOBAL_AGENT.HTTP_PROXY` configuration value: URL must not have query.');
  }

  if (urlTokens.hash !== null) {
    throw new UnexpectedStateError('Unsupported `GLOBAL_AGENT.HTTP_PROXY` configuration value: URL must not have hash.');
  }

  if (urlTokens.protocol !== 'http:') {
    throw new UnexpectedStateError('Unsupported `GLOBAL_AGENT.HTTP_PROXY` configuration value: URL protocol must be "http:".');
  }

  let port = 80;

  if (urlTokens.port) {
    port = Number.parseInt(urlTokens.port, 10);
  }

  return {
    authorization: urlTokens.auth || null,
    hostname: urlTokens.hostname,
    port,
  };
};
