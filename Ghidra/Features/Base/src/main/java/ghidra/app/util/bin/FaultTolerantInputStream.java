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

import java.util.Arrays;
import java.util.function.BiConsumer;

import java.io.IOException;
import java.io.InputStream;

import ghidra.formats.gfilesystem.FSUtilities;
import ghidra.util.Msg;

/**
 * An InputStream wrapper that suppresses any {@link IOException}s thrown by the wrapped stream
 * and starts returning 0 value bytes for all subsequent reads.
 */
public class FaultTolerantInputStream extends InputStream {

	private InputStream delegate;
	private long currentPosition;
	private long totalLength;
	private Throwable error;
	private long faultPosition;
	private long faultByteCount;
	private BiConsumer<String, Throwable> errorConsumer;

	/**
	 * Creates instance.
	 * 
	 * @param delegate {@link InputStream} to wrap
	 * @param length expected length of the stream
	 * @param errorConsumer consumer that will accept errors, if null Msg.error() will be used
	 */
	public FaultTolerantInputStream(InputStream delegate, long length,
			BiConsumer<String, Throwable> errorConsumer) {
		this.delegate = delegate;
		this.totalLength = length;
		this.errorConsumer = errorConsumer != null ? errorConsumer : this::defaultErrorHandler;
	}

	@Override
	public void close() throws IOException {
		FSUtilities.uncheckedClose(delegate, null);
		if (error != null) {
			errorConsumer.accept(
				"Errors encountered when reading at position %d, %d bytes faulted, replaced with 0's"
						.formatted(faultPosition, faultByteCount),
				error);
		}
	}

	private void defaultErrorHandler(String msg, Throwable th) {
		Msg.error(this, msg, th);
	}

	@Override
	public int read() throws IOException {
		byte[] buffer = new byte[1];
		int bytesRead = read(buffer, 0, 1);
		return bytesRead == 1 ? Byte.toUnsignedInt(buffer[0]) : -1;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		if (error == null) {
			// haven't hit an error yet, try to read normally
			try {
				int bytesRead = delegate.read(b, off, len);
				currentPosition += bytesRead;
				return bytesRead;
			}
			catch (IOException e) {
				faultPosition = currentPosition;
				error = e;
			}
		}

		// there was an error, return 0's from now on
		long remaining = totalLength - currentPosition;
		if (remaining <= 0) {
			return 0;
		}
		len = (int) Math.min(len, remaining);
		Arrays.fill(b, off, off + len, (byte) 0);
		currentPosition += len;
		faultByteCount += len;
		return len;
	}
}
