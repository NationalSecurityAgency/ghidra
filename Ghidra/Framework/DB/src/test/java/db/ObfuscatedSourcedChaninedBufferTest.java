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
package db;

import java.io.IOException;

public class ObfuscatedSourcedChaninedBufferTest extends AbstractChainedBufferTest {

	private static final int SOURCE_OFFSET = 24;

	public ObfuscatedSourcedChaninedBufferTest() {
		super(true, new Buffer() {

			@Override
			public int getId() {
				return 0;
			}

			@Override
			public int length() {
				return Integer.MAX_VALUE;
			}

			@Override
			public void get(int offset, byte[] bytes) throws IOException {
				for (int i = 0; i < bytes.length; i++) {
					bytes[i] = getByte(offset++);
				}
			}

			@Override
			public void get(int offset, byte[] data, int dataOffset, int length)
					throws IOException {
				for (int i = 0; i < length; i++) {
					data[dataOffset++] = getByte(offset++);
				}
			}

			@Override
			public byte[] get(int offset, int length) throws IOException {
				byte[] data = new byte[length];
				get(offset, data);
				return data;
			}

			@Override
			public byte getByte(int offset) throws IOException {
				return (byte) ~offset;
			}

			@Override
			public int getInt(int offset) throws IOException {
				byte[] data = get(offset, 4);
				return ((data[0] & 0xff) << 24) | ((data[1] & 0xff) << 16) |
					((data[2] & 0xff) << 8) | (data[3] & 0xff);
			}

			@Override
			public short getShort(int offset) throws IOException {
				byte[] data = get(offset, 2);
				return (short) (((data[0] & 0xff) << 8) | (data[1] & 0xff));
			}

			@Override
			public long getLong(int offset) throws IOException {
				byte[] data = get(offset, 8);
				return (((long) data[0] & 0xff) << 56) | (((long) data[1] & 0xff) << 48) |
					(((long) data[2] & 0xff) << 40) | (((long) data[3] & 0xff) << 32) |
					(((long) data[4] & 0xff) << 24) | (((long) data[5] & 0xff) << 16) |
					(((long) data[6] & 0xff) << 8) | ((long) data[7] & 0xff);
			}

			@Override
			public int put(int offset, byte[] data, int dataOffset, int length) throws IOException {
				return 0;
			}

			@Override
			public int put(int offset, byte[] bytes) throws IOException {
				return 0;
			}

			@Override
			public int putByte(int offset, byte b) throws IOException {
				return 0;
			}

			@Override
			public int putInt(int offset, int v) throws IOException {
				return 0;
			}

			@Override
			public int putShort(int offset, short v) throws IOException {
				return 0;
			}

			@Override
			public int putLong(int offset, long v) throws IOException {
				return 0;
			}

		}, SOURCE_OFFSET);
	}
}
