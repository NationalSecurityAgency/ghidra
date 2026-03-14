// @flow

import {
  parse as parseUrl,
} from 'url';
import matcher from 'matcher';
import {
  UnexpectedStateError,
} from '../errors';

export default (subjectUrl: string, noProxy: string) => {
  const subjectUrlTokens = parseUrl(subjectUrl);

  const rules = noProxy.split(/[\s,]+/);

  for (const rule of rules) {
    const ruleMatch = rule
      .replace(/^(?<leadingDot>\.)/, '*')
      .match(/^(?<hostname>.+?)(?::(?<port>\d+))?$/);

    if (!ruleMatch || !ruleMatch.groups) {
      throw new UnexpectedStateError('Invalid NO_PROXY pattern.');
    }

    if (!ruleMatch.groups.hostname) {
      throw new UnexpectedStateError('NO_PROXY entry pattern must include hostname. Use * to match any hostname.');
    }

    const hostnameIsMatch = matcher.isMatch(subjectUrlTokens.hostname, ruleMatch.groups.hostname);

    if (hostnameIsMatch && (!ruleMatch.groups || !ruleMatch.groups.port || subjectUrlTokens.port && subjectUrlTokens.port === ruleMatch.groups.port)) {
      return true;
    }
  }

  return false;
};
