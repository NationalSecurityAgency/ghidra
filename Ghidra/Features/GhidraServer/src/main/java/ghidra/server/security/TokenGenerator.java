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
import java.util.Date;

import generic.random.SecureRandomFactory;

public class TokenGenerator {

	static byte[] getNewToken(int size) {
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		byte[] token = new byte[size - 8];
		random.nextBytes(token);
		byte[] stampedToken = new byte[token.length + 8];
		System.arraycopy(token, 0, stampedToken, 8, token.length);
		putLong(stampedToken, 0, (new Date()).getTime());
		return stampedToken;
	}

	static boolean isRecentToken(byte[] token, long maxTime) {
		if (token.length < 8) {
			return false;
		}
		long diff = (new Date()).getTime() - getLong(token, 0);
		return (diff >= 0 && diff < maxTime);
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

}
