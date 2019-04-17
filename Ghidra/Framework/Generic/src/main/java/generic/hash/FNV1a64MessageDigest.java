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

public class FNV1a64MessageDigest extends AbstractMessageDigest {
	public static final long FNV_64_OFFSET_BASIS = 0xcbf29ce484222325L;
	public static final long FNV_64_PRIME = 1099511628211L;

	private long hashvalue;

	public FNV1a64MessageDigest() {
		super("FNV-1a", 8);
		init();
	}

	public FNV1a64MessageDigest(long initialVector) {
		super("FNV-1a", 8);
		hashvalue = initialVector;
	}

	private void init() {
		hashvalue = FNV_64_OFFSET_BASIS;
	}

	@Override
	public void update(byte[] input, int offset, int len) {
		for (int ii = 0; ii < len; ++ii) {
			hashvalue ^= (input[offset++] & 0xff);
			hashvalue *= FNV_64_PRIME;
		}
	}

	@Override
	public void update(byte[] input, int offset, int len, TaskMonitor monitor) {
		for (int ii = 0; ii < len; ++ii) {
			if (ii % 1000000 == 0 && monitor.isCancelled()) {
				break;
			}
			hashvalue ^= (input[offset++] & 0xff);
			hashvalue *= FNV_64_PRIME;
		}
	}

	@Override
	public void update(byte input) {
		hashvalue ^= input & 0xff;
		hashvalue *= FNV_64_PRIME;
	}

	@Override
	public int digest(byte[] buf, int offset, int len) {
		if (buf.length < 8 || len < 8) {
			offset += len - 1;
			hashvalue >>= 8 * (8 - len);
			for (int ii = 0; ii < len; ++ii) {
				buf[offset--] = (byte) (hashvalue & 0xff);
				hashvalue >>= 8;
			}
			init();
			return len;
		}

		// unwind the loop
		offset += 7;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		hashvalue >>= 8;
		buf[offset--] = (byte) (hashvalue & 0xff);
		init();
		return 8;
	}

	@Override
	public long digestLong() {
		long result = hashvalue;
		init();
		return result;
	}

	@Override
	public void reset() {
		init();
	}
}
