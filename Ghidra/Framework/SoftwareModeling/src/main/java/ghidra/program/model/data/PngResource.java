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
package ghidra.program.model.data;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;

import java.util.Arrays;
import java.util.zip.CRC32;

class PngResource {

	private static final int MAX_CHUNK_SIZE = 10 * 1024 * 1024;
	private static final byte[] IEND = new byte[] { 'I', 'E', 'N', 'D' };

	private MemBuffer buf;
	private int bufOffset;

	PngResource(MemBuffer buf) throws MemoryAccessException, InvalidDataTypeException {
		this.buf = buf;
		readHeader();
		scanContents();
	}

	int getLength() {
		return bufOffset;
	}

	private void scanContents() throws InvalidDataTypeException {
		int chunkCount = 0;
		byte[] type = new byte[4];
		int saveOffset = bufOffset;
		while (true) {
			try {
				int len = readInt();
				if (len < 0 || len > MAX_CHUNK_SIZE) {
					throw new InvalidDataTypeException("Invalid PNG Data - too big");
				}
				buf.getBytes(type, bufOffset);
				bufOffset += 4;
				byte[] data = new byte[len];
				buf.getBytes(data, bufOffset);
				bufOffset += len;
				long crc = readInt() & 0x00000000ffffffffL;
				if (!verifyCRC(type, data, crc)) {
					throw new InvalidDataTypeException("Invalid PNG Data - bad CRC");
				}
				saveOffset = bufOffset;
				++chunkCount;
				if (Arrays.equals(IEND, type)) {
					break;
				}
			}
			catch (MemoryAccessException e) {
				throw new InvalidDataTypeException("Invalid PNG Data - missing data");
			}
		}
		bufOffset = saveOffset;
		if (chunkCount == 0) {
			throw new InvalidDataTypeException("Invalid PNG Data - no data");
		}
	}

	private boolean verifyCRC(byte[] type, byte[] data, long crc) {
		CRC32 crc32 = new CRC32();
		crc32.update(type);
		crc32.update(data);
		long crcVal = crc32.getValue();
		return (crcVal == crc);
	}

	private void readHeader() throws MemoryAccessException, InvalidDataTypeException {
		long sig = readLong();
		if (sig != 0x89504e470d0a1a0aL) {
			throw new InvalidDataTypeException("Invalid PNG Data");
		}
	}

	private long readLong() throws MemoryAccessException {
		long val = 0;
		for (int i = 0; i < 8; i++) {
			val = val << 8;
			val |= buf.getByte(bufOffset++) & 0xff;
		}
		return val;
	}

	private int readInt() throws MemoryAccessException {
		int val = 0;
		for (int i = 0; i < 4; i++) {
			val = val << 8;
			val |= buf.getByte(bufOffset++) & 0xff;
		}
		return val;
	}

}
