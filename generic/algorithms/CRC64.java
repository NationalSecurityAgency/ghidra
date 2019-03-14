/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.algorithms;

public class CRC64 {

	private static final long poly = 0xC96C5795D7870F42L;
	private static final long crcTable[] = new long[256];

	private long crc = -1;

	static {
		for (int b = 0; b < crcTable.length; ++b) {
			long r = b;
			for (int i = 0; i < 8; ++i) {
				if ((r & 1) == 1)
					r = (r >>> 1) ^ poly;
				else
					r >>>= 1;
			}

			crcTable[b] = r;
		}
	}

	public void update(byte[] buf, int off, int len) {
		int end = off + len;

		while (off < end)
			crc = crcTable[(buf[off++] ^ (int) crc) & 0xFF] ^ (crc >>> 8);
	}

	public long finish() {
		long value = ~crc;
		crc = -1;
		return value;
	}

}
