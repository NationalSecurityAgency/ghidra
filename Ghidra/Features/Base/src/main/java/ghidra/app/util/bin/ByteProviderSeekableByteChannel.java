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
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SeekableByteChannel;

/**
 * Adapter between Ghidra {@link ByteProvider} and java nio {@link SeekableByteChannel}
 */
public class ByteProviderSeekableByteChannel implements SeekableByteChannel {

	protected ByteProvider bp;
	protected long position;

	public ByteProviderSeekableByteChannel(ByteProvider bp) {
		this.bp = bp;
	}

	@Override
	public boolean isOpen() {
		return bp != null;
	}

	@Override
	public void close() throws IOException {
		if (bp != null) {
			bp.close();
			bp = null;
		}
	}

	@Override
	public int read(ByteBuffer dst) throws IOException {
		ensureOpen();

		long bpRemaining = bp.length() - position;
		if (bpRemaining <= 0) {
			return -1;
		}

		int bufRemaining = dst.remaining();
		int bytesToRead = (int) Math.min(bufRemaining, bpRemaining);

		byte[] tmp = bp.readBytes(position, bytesToRead);

		dst.put(tmp, 0, tmp.length);

		position += tmp.length;
		return tmp.length;
	}

	@Override
	public int write(ByteBuffer src) throws IOException {
		throw new IOException("unimplemented");
	}

	@Override
	public long position() throws IOException {
		ensureOpen();
		return position;
	}

	@Override
	public SeekableByteChannel position(long newPosition) throws IOException {
		ensureOpen();
		this.position = newPosition;
		return this;
	}

	@Override
	public long size() throws IOException {
		ensureOpen();
		return bp.length();
	}

	@Override
	public SeekableByteChannel truncate(long size) throws IOException {
		throw new IOException("unimplemented");
	}

	private void ensureOpen() throws IOException {
		if (bp == null) {
			throw new ClosedChannelException();
		}
	}

}
