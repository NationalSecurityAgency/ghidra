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

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractMessageDigest implements MessageDigest {
	public final String algorithm;
	public final int digestLength;

	protected AbstractMessageDigest(String algorithm, int digestLength) {
		this.algorithm = algorithm;
		this.digestLength = digestLength;
	}

	@Override
	public final String getAlgorithm() {
		return algorithm;
	}

	@Override
	public final int getDigestLength() {
		return digestLength;
	}

	@Override
	public final byte[] digest() {
		byte[] results = new byte[digestLength];
		digest(results, 0, digestLength);
		return results;
	}

	@Override
	public final void update(byte[] input, TaskMonitor monitor) throws CancelledException {
		update(input, 0, input.length, monitor);
	}

	@Override
	public final void update(byte[] input) {
		update(input, 0, input.length);
	}

	@Override
	public void update(short input) {
		update((byte) ((input >> 8) & 0xff));
		update((byte) (input & 0xff));
	}

	@Override
	public void update(int input) {
		update((byte) ((input >> 24) & 0xff));
		update((byte) ((input >> 16) & 0xff));
		update((byte) ((input >> 8) & 0xff));
		update((byte) (input & 0xff));
	}

	@Override
	public void update(long input) {
		update((byte) ((input >> 56) & 0xff));
		update((byte) ((input >> 48) & 0xff));
		update((byte) ((input >> 40) & 0xff));
		update((byte) ((input >> 32) & 0xff));
		update((byte) ((input >> 24) & 0xff));
		update((byte) ((input >> 16) & 0xff));
		update((byte) ((input >> 8) & 0xff));
		update((byte) (input & 0xff));
	}

	/**
	 * You REALLY want to override this method.
	 */
	@Override
	public void update(byte[] input, int offset, int len) {
		for (int ii = 0; ii < len; ++ii) {
			update(input[offset++]);
		}
	}

	/**
	 * You REALLY want to override this method too.
	 * @throws CancelledException 
	 */
	@Override
	public void update(byte[] input, int offset, int len, TaskMonitor monitor)
			throws CancelledException {
		for (int ii = 0; ii < len; ++ii) {
			monitor.checkCanceled();
			update(input[offset++]);
		}
	}
}
