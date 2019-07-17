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
package ghidra.file.crypto;

public final class CryptoUtil {

	/**
	 * Translates an integer from host byte order to network byte order.
	 * @param value the integer value to translate
	 * @return the network byte order value
	 */
	public final static byte [] htonl(int value) {
		byte [] bytes = new byte[4];

		bytes[3] = (byte)((value >>  0) & 0xff);
		bytes[2] = (byte)((value >>  8) & 0xff);
		bytes[1] = (byte)((value >> 16) & 0xff);
		bytes[0] = (byte)((value >> 24) & 0xff);

		return bytes;
	}
}
