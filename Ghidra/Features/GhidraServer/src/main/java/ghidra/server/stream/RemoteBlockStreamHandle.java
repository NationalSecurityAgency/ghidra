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
import java.security.SecureRandom;

import javax.net.SocketFactory;
import javax.net.ssl.SSLSocketFactory;

import db.buffers.BlockStream;
import db.buffers.DataBuffer;
import generic.random.SecureRandomFactory;
import ghidra.util.StringUtilities;

/**
 * <code>RemoteBlockStreamHandle</code> provides a serializable handle to a
 * remote block stream. The handle is always instantiated by the server side and
 * passed to the client via remote serialization.
 * <p>
 * A single instance is used to serve both client and server roles at both ends
 * of the connection. The client side will invoke the {@link #openBlockStream()}
 * method which in turn will invoke the {@link #connect()} method which will
 * establish a connection to the remote server identified by the streamServer
 * information. The streamID and authenticationToken will be passed to the
 * server to facilitate proper association with the correct BlockStream.
 * <p>
 * On the server side, when this handle is instantiated it should be registered
 * with the {@link BlockStreamServer} together with the associated BlockStream
 * ({@link BlockStreamServer#registerBlockStream(RemoteBlockStreamHandle, BlockStream)}.
 * It is the job of this handle and the BlockStreamServer to associate an
 * accepted connection with the appropriate BlockStream.
 *
 * @param <T> InputBlockStream or OutputBlockStream
 */
public abstract class RemoteBlockStreamHandle<T extends BlockStream> implements Serializable {

	public static final long serialVersionUID = 1L;

	public static boolean enableCompressedSerializationOutput = Boolean.parseBoolean(
		System.getProperty(DataBuffer.COMPRESSED_SERIAL_OUTPUT_PROPERTY, "false"));

	public static final String HEADER_PREFIX = "@stream:";
	public static final String HEADER_SUFFIX = "@";
	public static final int HEADER_LENGTH =
		HEADER_PREFIX.length() + 16 + 16 + HEADER_SUFFIX.length();

	public static final String TERM_PREFIX = "@end:";
	public static final String TERM_SUFFIX = "@";
	public static final int TERM_LENGTH = TERM_PREFIX.length() + 16 + TERM_SUFFIX.length();

	private String streamServerIPAddress;
	private int streamServerPort;
	private long streamID;
	private long authenticationToken;
	private final int blockCount;
	private final int blockSize;

	protected final boolean compressed = enableCompressedSerializationOutput;

	private boolean connectionPending = true;

	/**
	 * Abstract RemoteBlockStreamHandle constructor
	 * @param server block stream server instance
	 * @param blockSize BufferFile block size
	 * @throws IOException
	 */
	public RemoteBlockStreamHandle(BlockStreamServer server, int blockCount, int blockSize)
			throws IOException {
		streamServerIPAddress = server.getServerHostname();
		if (!server.isRunning() || streamServerIPAddress == null) {
			throw new IOException("block stream server is not running");
		}
		streamServerPort = server.getServerPort();
		streamID = server.getNextStreamID();
		this.authenticationToken = getRandom();
		this.blockCount = blockCount;
		this.blockSize = blockSize;
	}

	/**
	 * Determine if a connection has not yet been requested for this handle.
	 * @return true if connection has not yet been requested by a client
	 */
	public synchronized boolean isPending() {
		return connectionPending;
	}

	/**
	 * Get the unique ID for this stream
	 * @return stream ID
	 */
	long getStreamID() {
		return streamID;
	}

	/**
	 * Get the authentication token value
	 * @return authentication token value
	 */
	long getAuthenticationToken() {
		return authenticationToken;
	}

	/**
	 * Get the number of blocks to be transferred
	 * @return block count
	 */
	public int getBlockCount() {
		return blockCount;
	}

	/**
	 * Get the raw block size
	 * @return block size
	 */
	int getBlockSize() {
		return blockSize;
	}

	/**
	 * Get the preferred socket send/receive buffer size to be used
	 * @return preferred socket send/receive buffer size
	 */
	protected int getPreferredBufferSize() {
		return (getBlockSize() + 4) * 12;
	}

	/**
	 * Generate a random number for use as a block stream authentication token.
	 * @return random value
	 */
	private static synchronized long getRandom() {
		SecureRandom random = SecureRandomFactory.getSecureRandom();
		return random.nextLong();
	}

	/**
	 * Get the stream request header to be sent when establishing the server
	 * connection.
	 * <pre>
	 * Format: "{@value #HEADER_PREFIX}xxxxxxxxxxxxxxxxXXXXXXXXXXXXXXXX{@value #HEADER_SUFFIX}"
	 *   where x's provide the stream ID as a hex value, and
	 *   X's provide the stream authentication token.
	 * </pre>
	 * @return stream request header
	 * @see BlockStreamServer
	 */
	private String getStreamRequestHeader() {
		StringBuilder buf = new StringBuilder();
		buf.append(HEADER_PREFIX);
		// streamID as 16-digit hex value
		buf.append(StringUtilities.pad(Long.toHexString(streamID), '0', 16));
		// authenticationToken as 16-digit hex value
		buf.append(StringUtilities.pad(Long.toHexString(authenticationToken), '0', 16));
		buf.append(HEADER_SUFFIX);
		return buf.toString();
	}

	/**
	 * Get the stream termination footer to be sent when ending the server
	 * connection.
	 * <pre>
	 * Format: "{@value #TERM_PREFIX}xxxxxxxxxxxxxxxx{@value #TERM_SUFFIX}"
	 *   where x's provide the stream ID as a hex value, and
	 *   X's provide the stream authentication token.
	 * </pre>
	 * @return stream termination footer
	 * @see BlockStreamServer
	 */
	private String getStreamTerminator() {
		StringBuilder buf = new StringBuilder();
		buf.append(TERM_PREFIX);
		// streamID as 16-digit hex value
		buf.append(StringUtilities.pad(Long.toHexString(streamID), '0', 16));
		buf.append(TERM_SUFFIX);
		return buf.toString();
	}

	/**
	 * Perform verification of termination footer bytes
	 * @param terminatorBytes bytes read as stream terminator
	 * @throws IOException
	 */
	void checkTerminator(byte[] terminatorBytes) throws IOException {
		String term = new String(terminatorBytes);
		if (terminatorBytes.length != TERM_LENGTH) {
			throw new IllegalArgumentException("invalid terminatorBytes length");
		}
		if (!term.startsWith(TERM_PREFIX) || !term.endsWith(TERM_SUFFIX)) {
			throw new IOException("invalid block stream terminator");
		}
		String streamIdStr = term.substring(TERM_PREFIX.length(), TERM_PREFIX.length() + 16);
		try {
			if (streamID != Long.parseUnsignedLong(streamIdStr, 16)) {
				throw new IOException("invalid block stream terminator stream ID");
			}
		}
		catch (NumberFormatException e) {
			throw new IOException("invalid block stream terminator stream ID: " + streamIdStr);
		}
	}

	/**
	 * <code>StreamRequest</code> is used to wrap the stream request
	 * registration data
	 */
	static class StreamRequest {
		final long streamID;
		final long authenticationToken;

		/**
		 * Construct a stream request object
		 * @param streamID assigned stream ID
		 * @param authenticationToken token to be used during client connection authentication
		 */
		StreamRequest(long streamID, long authenticationToken) {
			this.streamID = streamID;
			this.authenticationToken = authenticationToken;
		}
	}

	/**
	 * Parse a block stream connection header to obtain the stream ID
	 * @param headerBytes stream request header sent by client
	 * @return StreamRequest containing stream ID and authentication token
	 * @throws IOException if header parse fails
	 */
	static StreamRequest parseStreamRequestHeader(byte[] headerBytes) throws IOException {
		String head = new String(headerBytes);
		if (headerBytes.length != HEADER_LENGTH) {
			throw new IllegalArgumentException("invalid headerBytes length");
		}
		if (!head.startsWith(HEADER_PREFIX) || !head.endsWith(HEADER_SUFFIX)) {
			throw new IOException("invalid block stream header");
		}
		String streamIdStr = head.substring(HEADER_PREFIX.length(), HEADER_PREFIX.length() + 16);
		String authTokenStr =
			head.substring(HEADER_PREFIX.length() + 16, HEADER_PREFIX.length() + 32);
		try {
			long streamID = Long.parseUnsignedLong(streamIdStr, 16);
			long authToken = Long.parseUnsignedLong(authTokenStr, 16);
			return new StreamRequest(streamID, authToken);
		}
		catch (NumberFormatException e) {
			throw new IOException("invalid request header stream ID: " + streamIdStr);
		}
	}

	/**
	 * Invoked by client during the openBlockStream operation and completes the
	 * connection into the server.
	 * @return connected socket
	 * @throws IOException
	 */
	protected Socket connect() throws IOException {

		synchronized (this) {
			if (!connectionPending) {
				throw new IOException("already connected");
			}
			connectionPending = false;
		}

		SocketFactory socketFactory = SSLSocketFactory.getDefault();
		Socket socket = socketFactory.createSocket(streamServerIPAddress, streamServerPort);

		// TODO: set socket options ?

		// write stream connection request info
		OutputStream out = socket.getOutputStream();
		out.write(getStreamRequestHeader().getBytes());
		out.flush();

		return socket;
	}

	/**
	 * Send the stream termination footer bytes over the socket.
	 * @param socket connected socket
	 * @throws IOException
	 */
	protected void writeStreamEnd(Socket socket) throws IOException {
		OutputStream out = socket.getOutputStream();
		out.write(getStreamTerminator().getBytes());
		out.flush();
	}

	/**
	 * Read the stream terminator from the socket. Timeout should be disabled
	 * for the side which has written the stream to the socket output.
	 * @param socket connected socket
	 * @param enableTimeout true if timeout should be used on read, else false
	 *            TODO: no timeouts currently used (relies on BufferFile handle)
	 * @throws IOException
	 * @throws EOFException if stream terminated unexpectedly (e.g., cancelled)
	 */
	protected void readStreamEnd(Socket socket, boolean enableTimeout) throws IOException {
		InputStream in = socket.getInputStream();
		byte[] term = new byte[TERM_LENGTH];
		int total = 0;
		// TODO: no timeout currently employed - if we do we need to prevent timeout here
		// if (!enableTimeout) {
		// socket.setSoTimeout(0);
		// }
		while (total < term.length) {
			int readlen = in.read(term, total, term.length - total);
			if (readlen < 0) {
				throw new EOFException("unexpected end of stream");
			}
			total += readlen;
		}
		checkTerminator(term);
	}

	/**
	 * Invoked by {@link BlockStreamServer} to complete the socket to
	 * BlockStream connection. This method should be called from its own
	 * runnable and will block until the block stream is closed.
	 * @param socket connected socket
	 * @param blockStream open block stream
	 * @throws IOException
	 * @throws EOFException if stream terminated unexpectedly (e.g., cancelled)
	 */
	abstract void serveBlockStream(Socket socket, BlockStream blockStream) throws IOException;

}
