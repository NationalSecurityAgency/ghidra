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
package ghidra.file.formats.android.dex.format;

import java.io.*;

/**
 * https://source.android.com/devices/tech/dalvik/dex-format#mutf-8
 * <br>
 * Modified version of:
 * <br>
 * https://android.googlesource.com/platform/libcore/+/7047230/dex/src/main/java/com/android/dex/Mutf8.java
 */
public final class ModifiedUTF8 {

	/**
	 * Decodes a null-terminated MUTF-8 string from the given stream.
	 * <p>
	 * The decoded string grows as bytes are consumed, so its length is bounded by the number of
	 * bytes available in the stream rather than by any (possibly untrusted) declared length.
	 *
	 * @param in the stream to read MUTF-8 bytes from
	 * @return the decoded string
	 * @throws UTFDataFormatException if the bytes are not valid MUTF-8
	 * @throws IOException if an IO-related error occurred
	 */
	public final static String decode(InputStream in) throws UTFDataFormatException, IOException {
		StringBuilder sb = new StringBuilder();
		while (true) {
			char a = (char) (in.read() & 0xff);
			if (a == 0) {
				return sb.toString();
			}
			if (a < '\u0080') {
				sb.append(a);
			}
			else if ((a & 0xe0) == 0xc0) {
				int b = in.read() & 0xff;
				if ((b & 0xC0) != 0x80) {
					throw new UTFDataFormatException("bad second byte");
				}
				sb.append((char) (((a & 0x1F) << 6) | (b & 0x3F)));
			}
			else if ((a & 0xf0) == 0xe0) {
				int b = in.read() & 0xff;
				int c = in.read() & 0xff;
				if (((b & 0xC0) != 0x80) || ((c & 0xC0) != 0x80)) {
					throw new UTFDataFormatException("bad second or third byte");
				}
				sb.append((char) (((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F)));
			}
			else {
				throw new UTFDataFormatException("bad byte");
			}
		}
	}
}
