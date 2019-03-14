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
import java.io.InputStream;

/**
 * Wraps a {@link ByteProvider} and presents it as an {@link InputStream}.
 * <p>
 * This InputStream will be limited to a region of the underlying ByteProvider, and
 * has an optional amount of padding at the end of the stream where the stream will appear
 * to have bytes with a value of zero.
 */
public class ByteProviderPaddedInputStream extends InputStream {
	private ByteProvider provider;
	private long currentBPOffset;

	private long bpEndOffset;
	private long bpEndPadOffset;

	/**
	 * Create a new {@link ByteProviderInputStream} instance, using the specified
	 * {@link ByteProvider} as the source of the bytes returned from this stream.
	 * <p>
	 * The source ByteProvider is not closed when this stream is closed.
	 * <p>
	 * The total number of bytes that can be read from this instance will be length + padCount.
	 * <p>
	 * @param provider the {@link ByteProvider} to wrap.
	 * @param startOffset the starting offset in the ByteProvider.
	 * @param length the number of bytes from the {@link ByteProvider} to allow to be read by this InputStream.
	 * @param padCount the number of fake zero bytes to add after the real {@code length} bytes.
	 */
	public ByteProviderPaddedInputStream(ByteProvider provider, long startOffset, long length,
			long padCount) {
		this.provider = provider;
		this.currentBPOffset = startOffset;
		this.bpEndOffset = startOffset + length;
		this.bpEndPadOffset = bpEndOffset + padCount;
	}

	@Override
	public void close() {
		// the provider is not closed.
	}

	@Override
	public int read() throws IOException {
		if (currentBPOffset < bpEndOffset) {
			return provider.readByte(currentBPOffset++) & 0xff;
		}
		else if (currentBPOffset < bpEndPadOffset) {
			currentBPOffset++;
			return 0;
		}
		return -1;
	}

	@Override
	public int available() {
		return (int) Math.min(bpEndPadOffset - currentBPOffset, Integer.MAX_VALUE);
	}
}
