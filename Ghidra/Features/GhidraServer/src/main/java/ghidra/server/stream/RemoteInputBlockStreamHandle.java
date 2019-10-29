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
 * <code>RemoteInputBlockStreamHandle</code> provides a serializable handle to a
 * remote input block stream. The handle is always instantiated by the server side and
 * passed to the client via remote serialization.
 */
public class RemoteInputBlockStreamHandle extends RemoteBlockStreamHandle<InputBlockStream>
		implements BlockStreamHandle<InputBlockStream> {

	@SuppressWarnings("hiding")
	public static final long serialVersionUID = 1L;

	private boolean includesHeaderBlock;

	/**
	 * Construct a remote input block stream handle for reading BufferFile blocks
	 * residing on the server. 
	 * @param server block stream server instance
	 * @param inputBlockStream input block stream
	 * @throws IOException
	 */
	public RemoteInputBlockStreamHandle(BlockStreamServer server, InputBlockStream inputBlockStream)
			throws IOException {
		super(server, inputBlockStream.getBlockCount(), inputBlockStream.getBlockSize());
		this.includesHeaderBlock = inputBlockStream.includesHeaderBlock();
	}

	/**
	 * <code>ClientInputBlockStream</code> provides the client-side of an
	 * InputBlockStream which wraps an optionally compressed socket input stream
	 */
	private class ClientInputBlockStream implements InputBlockStream {

		private final Socket socket;
		private final InputStream in;

		private int blocksRemaining = getBlockCount();

		ClientInputBlockStream(Socket socket) throws IOException {
			this.socket = socket;
			in = compressed ? new InflaterInputStream(socket.getInputStream())
					: socket.getInputStream();
		}

		@Override
		public void close() throws IOException {
			in.close();
			socket.close();
		}

		@Override
		public BufferFileBlock readBlock() throws IOException {
			if (blocksRemaining == 0) {
				return null;
			}

			byte[] bytes = new byte[getBlockSize() + 4]; // include space for index
			int total = 0;
			while (total < bytes.length) {
				int readlen = in.read(bytes, total, bytes.length - total);
				if (readlen < 0) {
					throw new EOFException("unexpected end of stream");
				}
				total += readlen;
			}

			if (--blocksRemaining == 0) {
				// perform final handshake before returning final block
				if (compressed && in.read() != -1) {
					// failed to properly exhaust compressed stream
					throw new IOException("expected end of compressed stream");
				}
				readStreamEnd(socket, true);
				writeStreamEnd(socket);
			}
			return new BufferFileBlock(bytes);
		}

		@Override
		public boolean includesHeaderBlock() {
			return includesHeaderBlock;
		}

		@Override
		public int getBlockCount() {
			return RemoteInputBlockStreamHandle.this.getBlockCount();
		}

		@Override
		public int getBlockSize() {
			return RemoteInputBlockStreamHandle.this.getBlockSize();
		}
	}

	@Override
	public InputBlockStream openBlockStream() throws IOException {

		Socket socket = connect();
		socket.setReceiveBufferSize(getPreferredBufferSize());

		return new ClientInputBlockStream(socket);
	}

	@Override
	void serveBlockStream(Socket socket, BlockStream blockStream) throws IOException {
		if (!(blockStream instanceof InputBlockStream)) {
			throw new IllegalArgumentException("expected InputBlockStream");
		}

		socket.setSendBufferSize(getPreferredBufferSize());

		InputBlockStream inputBlockStream = (InputBlockStream) blockStream;
		try (OutputStream out = socket.getOutputStream()) {

			copyBlockData(inputBlockStream, out);

			// perform final handshake before close (uncompressed)
			writeStreamEnd(socket);
			readStreamEnd(socket, false);
		}
		catch (SocketException e) {
			// remain silent if socket closed by client
			if (e.getMessage().startsWith("Broken pipe")) {
				throw new EOFException("unexpected end of stream");
			}
			throw e;
		}
	}

	private void copyBlockData(InputBlockStream inputBlockStream, OutputStream out)
			throws IOException {

		if (compressed) {
			out = new DeflaterOutputStream(out, new Deflater(Deflater.BEST_SPEED));
		}

		int blocksRemaining = getBlockCount();

		BufferFileBlock block;
		while ((block = inputBlockStream.readBlock()) != null) {
			if (blocksRemaining == 0) {
				throw new IOException("unexpected data in stream");
			}
			out.write(block.toBytes());
			--blocksRemaining;
		}

		// done with compressed stream, force compressed data to flush
		if (out instanceof DeflaterOutputStream) {
			((DeflaterOutputStream) out).finish();
		}
	}

}
