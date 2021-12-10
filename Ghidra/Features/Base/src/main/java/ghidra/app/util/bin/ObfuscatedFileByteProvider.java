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
package ghidra.app.util.bin;

import java.io.File;
import java.io.IOException;
import java.nio.file.AccessMode;

import ghidra.formats.gfilesystem.FSRL;

/**
 * A {@link ByteProvider} that reads from an on-disk file, but obfuscates / de-obfuscates the
 * contents of the file when reading / writing.
 */
public class ObfuscatedFileByteProvider extends FileByteProvider {

	// @formatter:off
	// copied from ChainedBuffer
	static final byte[] XOR_MASK_BYTES = new byte[] {
		(byte)0x59, (byte)0xea, (byte)0x67, (byte)0x23, (byte)0xda, (byte)0xb8, (byte)0x00, (byte)0xb8, 
		(byte)0xc3, (byte)0x48, (byte)0xdd, (byte)0x8b, (byte)0x21, (byte)0xd6, (byte)0x94, (byte)0x78, 
		(byte)0x35, (byte)0xab, (byte)0x2b, (byte)0x7e, (byte)0xb2, (byte)0x4f, (byte)0x82, (byte)0x4e, 
		(byte)0x0e, (byte)0x16, (byte)0xc4, (byte)0x57, (byte)0x12, (byte)0x8e, (byte)0x7e, (byte)0xe6, 
		(byte)0xb6, (byte)0xbd, (byte)0x56, (byte)0x91, (byte)0x57, (byte)0x72, (byte)0xe6, (byte)0x91, 
		(byte)0xdc, (byte)0x52, (byte)0x2e, (byte)0xf2, (byte)0x1a, (byte)0xb7, (byte)0xd6, (byte)0x6f, 
		(byte)0xda, (byte)0xde, (byte)0xe8, (byte)0x48, (byte)0xb1, (byte)0xbb, (byte)0x50, (byte)0x6f, 
		(byte)0xf4, (byte)0xdd, (byte)0x11, (byte)0xee, (byte)0xf2, (byte)0x67, (byte)0xfe, (byte)0x48, 
		(byte)0x8d, (byte)0xae, (byte)0x69, (byte)0x1a, (byte)0xe0, (byte)0x26, (byte)0x8c, (byte)0x24, 
		(byte)0x8e, (byte)0x17, (byte)0x76, (byte)0x51, (byte)0xe2, (byte)0x60, (byte)0xd7, (byte)0xe6, 
		(byte)0x83, (byte)0x65, (byte)0xd5, (byte)0xf0, (byte)0x7f, (byte)0xf2, (byte)0xa0, (byte)0xd6, 
		(byte)0x4b, (byte)0xbd, (byte)0x24, (byte)0xd8, (byte)0xab, (byte)0xea, (byte)0x9e, (byte)0xa6, 
		(byte)0x48, (byte)0x94, (byte)0x3e, (byte)0x7b, (byte)0x2c, (byte)0xf4, (byte)0xce, (byte)0xdc, 
		(byte)0x69, (byte)0x11, (byte)0xf8, (byte)0x3c, (byte)0xa7, (byte)0x3f, (byte)0x5d, (byte)0x77, 
		(byte)0x94, (byte)0x3f, (byte)0xe4, (byte)0x8e, (byte)0x48, (byte)0x20, (byte)0xdb, (byte)0x56, 
		(byte)0x32, (byte)0xc1, (byte)0x87, (byte)0x01, (byte)0x2e, (byte)0xe3, (byte)0x7f, (byte)0x40,
		
	};
	// @formatter:on

	/**
	 * Creates an instance of {@link ObfuscatedFileByteProvider}.
	 * 
	 * @param file {@link File} to read from / write to
	 * @param fsrl {@link FSRL} identity of this file
	 * @param accessMode {@link AccessMode#READ} or {@link AccessMode#WRITE}
	 * @throws IOException if error
	 */
	public ObfuscatedFileByteProvider(File file, FSRL fsrl, AccessMode accessMode)
			throws IOException {
		super(file, fsrl, accessMode);
	}

	@Override
	public File getFile() {
		// obfuscated file isn't readable, so force null
		return null;
	}

	@Override
	protected int doReadBytes(long index, byte[] buffer) throws IOException {
		int bytesRead = super.doReadBytes(index, buffer);
		for (int i = 0; i < bytesRead; i++) {
			long byteIndex = index + i;
			int xorMaskIndex = (int) (byteIndex % XOR_MASK_BYTES.length);
			byte xorMask = XOR_MASK_BYTES[xorMaskIndex];
			buffer[i] ^= xorMask;
		}
		return bytesRead;
	}

	@Override
	protected void doWriteBytes(long index, byte[] buffer, int offset, int length)
			throws IOException {
		byte[] tmpBuffer = new byte[length];
		for (int i = 0; i < length; i++) {
			long byteIndex = index + i;
			int xorMaskIndex = (int) (byteIndex % XOR_MASK_BYTES.length);
			byte xorMask = XOR_MASK_BYTES[xorMaskIndex];
			tmpBuffer[i] = (byte) (buffer[i + offset] ^ xorMask);
		}
		super.doWriteBytes(index, tmpBuffer, 0, length);
	}

}
