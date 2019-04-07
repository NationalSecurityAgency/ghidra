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
package generic.hash;

import ghidra.util.task.TaskMonitor;

public class FNV1a32MessageDigest extends AbstractMessageDigest {
	public static final int FNV_32_OFFSET_BASIS = 0x811c9dc5;
	public static final int FNV_32_PRIME = 16777619;

	private int hashvalue;

	public FNV1a32MessageDigest(int initialVector) {
		super("FNV-1a", 4);
		hashvalue = initialVector;
	}

	public FNV1a32MessageDigest() {
		super("FNV-1a", 4);
		init();
	}

	private void init() {
		hashvalue = FNV_32_OFFSET_BASIS;
	}

	@Override
	public void update(byte[] input, int offset, int len) {
		for (int ii = 0; ii < len; ++ii) {
			hashvalue ^= (input[offset++] & 0xff);
			hashvalue *= FNV_32_PRIME;
		}
	}

	@Override
	public void update(byte[] input, int offset, int len, TaskMonitor monitor) {
		for (int ii = 0; ii < len; ++ii) {
			if (ii % 1000000 == 0 && monitor.isCancelled()) {
				break;
			}
			hashvalue ^= (input[offset++] & 0xff);
			hashvalue *= FNV_32_PRIME;
		}
	}

	@Override
	public void update(byte input) {
		hashvalue ^= input & 0xff;
		hashvalue *= FNV_32_PRIME;
	}

	@Override
	public int digest(byte[] buf, int offset, int len) {
		if (buf.length < 4 || len < 4) {
			offset += len - 1;
			hashvalue >>= 8 * (4 - len);
			for (int ii = 0; ii < len; ++ii) {
				buf[offset--] = (byte) (hashvalue & 0xff);
				hashvalue >>= 8;
			}
			init();
			return len;
		}

		// unwind the loop
		offset += 3;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		init();
		return 4;
	}

	@Override
	public long digestLong() {
		long result = hashvalue & 0x00000000ffffffffL;
		init();
		return result;
	}

	@Override
	public void reset() {
		init();
	}
}
