/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.server.security;

import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;

import generic.random.SecureRandomFactory;

public class TokenGenerator {

	private static final long MAX_TTL_MS = 60_000; // max token time-to-live 60s

	private static final int TOKEN_SIZE = 64;

	private static CachedTokenSet tokenCache = new CachedTokenSet();

	/**
	 * {@return a single-use token byte sequence with embedded timestamp}
	 */
	static byte[] getNewToken() {
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		byte[] token = new byte[TOKEN_SIZE - 8];
		random.nextBytes(token);
		byte[] stampedToken = new byte[TOKEN_SIZE];
		System.arraycopy(token, 0, stampedToken, 8, token.length);
		putLong(stampedToken, 0, (new Date()).getTime());
		tokenCache.add(stampedToken);
		return stampedToken;
	}

	/**
	 * Determine if the specified token has not yet been consumed and is still valid.
	 * <p>
	 * NOTE: This method may only be invoked once per token after which the token will become
	 * invalid.
	 * 
	 * @param token token previously issued
	 * @return true if token is valid and now consumed
	 */
	static boolean isValidToken(byte[] token) {
		if (token.length != TOKEN_SIZE || !tokenCache.consume(token)) {
			return false;
		}
		long issueTime = getLong(token, 0);
		if (issueTime <= 0) {
			return false;
		}
		long diff = (new Date()).getTime() - issueTime;
		return (diff >= 0 && diff < MAX_TTL_MS);
	}

	private static long getLong(byte[] data, int offset) {
		return (((long) data[offset] & 0xff) << 56) | (((long) data[++offset] & 0xff) << 48) |
			(((long) data[++offset] & 0xff) << 40) | (((long) data[++offset] & 0xff) << 32) |
			(((long) data[++offset] & 0xff) << 24) | (((long) data[++offset] & 0xff) << 16) |
			(((long) data[++offset] & 0xff) << 8) | ((long) data[++offset] & 0xff);
	}

	private static int putLong(byte[] data, int offset, long v) {
		data[offset] = (byte) (v >> 56);
		data[++offset] = (byte) (v >> 48);
		data[++offset] = (byte) (v >> 40);
		data[++offset] = (byte) (v >> 32);
		data[++offset] = (byte) (v >> 24);
		data[++offset] = (byte) (v >> 16);
		data[++offset] = (byte) (v >> 8);
		data[++offset] = (byte) v;
		return ++offset;
	}

	/**
	 * {@link Token} provides a byte array token wrapper to facilitate value-based
	 * hashcode and equality when used as a map key.
	 */
	private static class Token {
		private byte[] token;

		Token(byte[] token) {
			this.token = token;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + Arrays.hashCode(token);
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			Token other = (Token) obj;
			return Arrays.equals(token, other.token);
		}
	}

	/**
	 * {@link CachedTokenSet} tracks timed token issuance and insures that they remain
	 * valid for one-time consumption within limited life-span.
	 */
	private static class CachedTokenSet {

		private final Map<Token, Long> cache = new ConcurrentHashMap<>();
		private final ScheduledExecutorService scheduler =
			Executors.newSingleThreadScheduledExecutor();

		CachedTokenSet() {
			// Perform token cleanup every 5-seconds
			scheduler.scheduleAtFixedRate(this::cleanup, 5, 5, TimeUnit.SECONDS);
		}

		void add(byte[] token) {
			cache.put(new Token(token), System.currentTimeMillis());
		}

		boolean consume(byte[] token) {
			Long storedAt = cache.remove(new Token(token)); // remove on retrieval
			if (storedAt == null)
				return false;
			return (System.currentTimeMillis() - storedAt < MAX_TTL_MS);
		}

		private void cleanup() {
			long now = System.currentTimeMillis();
			cache.entrySet().removeIf(e -> now - e.getValue() >= MAX_TTL_MS);
		}
	}
}
