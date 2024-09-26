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
package ghidra.features.base.memsearch.bytesequence;

public class ByteArrayByteSequence implements ByteSequence {

	private final byte[] bytes;

	public ByteArrayByteSequence(byte... bytes) {
		this.bytes = bytes;
	}

	@Override
	public int getLength() {
		return bytes.length;
	}

	@Override
	public byte getByte(int i) {
		return bytes[i];
	}

	@Override
	public byte[] getBytes(int index, int size) {
		if (index < 0 || index + size > bytes.length) {
			throw new IndexOutOfBoundsException();
		}
		byte[] results = new byte[size];
		System.arraycopy(bytes, index, results, 0, size);
		return results;
	}

	@Override
	public boolean hasAvailableBytes(int index, int length) {
		return index >= 0 && index + length <= getLength();
	}

}
