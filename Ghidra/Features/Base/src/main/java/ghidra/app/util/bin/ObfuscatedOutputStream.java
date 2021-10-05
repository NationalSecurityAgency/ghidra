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

import java.io.IOException;
import java.io.OutputStream;

/**
 * An {@link OutputStream} wrapper that obfuscates the bytes being written to the underlying
 * stream.
 */
public class ObfuscatedOutputStream extends OutputStream {

	private OutputStream delegate;
	private long currentPosition;

	/**
	 * Creates instance.
	 * 
	 * @param delegate {@link OutputStream} to wrap
	 */
	public ObfuscatedOutputStream(OutputStream delegate) {
		this.delegate = delegate;
	}

	@Override
	public void close() throws IOException {
		delegate.close();
		super.close();
	}

	@Override
	public void flush() throws IOException {
		delegate.flush();
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		byte[] tmpBuffer = new byte[len];
		for (int i = 0; i < len; i++) {
			long byteIndex = currentPosition + i;
			int xorMaskIndex =
				(int) (byteIndex % ObfuscatedFileByteProvider.XOR_MASK_BYTES.length);
			byte xorMask = ObfuscatedFileByteProvider.XOR_MASK_BYTES[xorMaskIndex];
			tmpBuffer[i] = (byte) (b[i + off] ^ xorMask);
		}
		delegate.write(tmpBuffer, 0, tmpBuffer.length);
		currentPosition += len;
	}

	@Override
	public void write(int b) throws IOException {
		write(new byte[] { (byte) b }, 0, 1);
	}

}
