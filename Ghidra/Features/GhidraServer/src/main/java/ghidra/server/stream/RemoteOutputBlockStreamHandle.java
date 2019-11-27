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
package ghidra.server.stream;

import java.io.*;
import java.net.Socket;
import java.net.SocketException;
import java.util.zip.*;

import db.buffers.*;

/**
 * <code>RemoteOutputBlockStreamHandle</code> provides a serializable handle to a
 * remote output block stream. The handle is always instantiated by the server side and
 * passed to the client via remote serialization.
 */
public class RemoteOutputBlockStreamHandle extends RemoteBlockStreamHandle<OutputBlockStream>
		implements BlockStreamHandle<OutputBlockStream> {

	@SuppressWarnings("hiding")
	public static final long serialVersionUID = 1L;

	/**
	 * Construct a remote output block stream handle for writing blocks to a
	 * BufferFile residing on the server.
	 * @param server block stream server instance
	 * @param blockCount number of blocks to be read by server and written by client
	 * @param blockSize buffer file block size
	 * @throws IOException
	 */
	public RemoteOutputBlockStreamHandle(BlockStreamServer server, int blockCount, int blockSize)
			throws IOException {
		super(server, blockCount, blockSize);
	}

	/**
	 * <code>ClientInputBlockStream</code> provides the client-side of an
	 * OutputBlockStream which wraps an optionally compressed socket output
	 * stream
	 */
	private class ClientOutputBlockStream implements OutputBlockStream {

		private final Socket socket;
		private final OutputStream out;

		private int blocksRemaining = getBlockCount();

		ClientOutputBlockStream(Socket socket) throws IOException {
			this.socket = socket;
			out = compressed
					? new DeflaterOutputStream(socket.getOutputStream(),
						new Deflater(Deflater.BEST_SPEED))
					: socket.getOutputStream();
		}

		@Override
		public int getBlockCount() {
			return RemoteOutputBlockStreamHandle.this.getBlockCount();
		}

		@Override
		public int getBlockSize() {
			return RemoteOutputBlockStreamHandle.this.getBlockSize();
		}

		@Override
		public void close() throws IOException {
			out.close();
			socket.close();
		}

		@Override
		public void writeBlock(BufferFileBlock block) throws IOException {
			if (blocksRemaining == 0) {
				throw new EOFException("unexpected data in stream");
			}

			out.write(block.toBytes());

			if (--blocksRemaining == 0) {

				// done with compressed stream, force compressed data to flush
				if (out instanceof DeflaterOutputStream) {
					((DeflaterOutputStream) out).finish();
				}

				// perform final handshake after final write
				writeStreamEnd(socket);
				readStreamEnd(socket, false);
			}
		}
	}

	@Override
	public OutputBlockStream openBlockStream() throws IOException {

		Socket socket = connect();
		socket.setSendBufferSize(getPreferredBufferSize());

		return new ClientOutputBlockStream(socket);
	}

	@Override
	void serveBlockStream(Socket socket, BlockStream blockStream) throws IOException {

		if (!(blockStream instanceof OutputBlockStream)) {
			throw new IllegalArgumentException("expected OutputBlockStream");
		}

		socket.setReceiveBufferSize(getPreferredBufferSize());

		OutputBlockStream outputBlockStream = (OutputBlockStream) blockStream;
		try (InputStream in = socket.getInputStream()) {

			copyBlockData(outputBlockStream, in);

			// perform final handshake (uncompressed)

			readStreamEnd(socket, true);

			// Need to close blockStream while client is waiting for final stream end 
			// indicator. This is needed so that the server-based file is fully written 
			// before the client is let loose from the handshake
			outputBlockStream.close();

			writeStreamEnd(socket);
		}
		catch (SocketException e) {
			// remain silent if socket closed by client (e.g., cancelled)
			if (e.getMessage().startsWith("Broken pipe")) {
				throw new EOFException("unexpected end of stream");
			}
			throw e;
		}

	}

	private void copyBlockData(OutputBlockStream outputBlockStream, InputStream in)
			throws IOException, EOFException {

		if (compressed) {
			in = new InflaterInputStream(in);
		}

		int blocksRemaining = getBlockCount();

		byte[] bytes = new byte[getBlockSize() + 4]; // include space for index
		while (blocksRemaining > 0) {
			int total = 0;
			while (total < bytes.length) {
				int readlen = in.read(bytes, total, bytes.length - total);
				if (readlen < 0) {
					throw new EOFException("unexpected end of stream");
				}
				total += readlen;
			}

			BufferFileBlock block = new BufferFileBlock(bytes);
			outputBlockStream.writeBlock(block);
			--blocksRemaining;
		}
		if (compressed && in.read() != -1) {
			// failed to properly exhaust compressed stream
			throw new IOException("expected end of compressed stream");
		}
	}
}
