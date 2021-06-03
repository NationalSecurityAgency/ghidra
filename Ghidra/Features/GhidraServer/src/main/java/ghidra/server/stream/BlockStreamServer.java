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
import java.net.*;
import java.util.HashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import db.buffers.BlockStream;
import db.buffers.InputBlockStream;
import ghidra.server.remote.ServerPortFactory;
import ghidra.server.stream.RemoteBlockStreamHandle.StreamRequest;
import ghidra.util.StringUtilities;
import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 * <code>BlockStreamServer</code> provides a block stream server implementation intended for 
 * integration with the RMI GhidraServer implementation.  The default instance will obtain its 
 * port from the {@link ServerPortFactory} while all instances will bind to the default 
 * {@link InetAddress#getLocalHost()} or the host address specified via the RMI property
 * <code>java.rmi.server.hostname</code> which is set via the GhidraServer -ip command
 * line option.
 * <p>
 * The server will run in its own thread with each accepted connection running in another thread.
 */
public class BlockStreamServer extends Thread {

	private static Logger log = LogManager.getLogger(BlockStreamServer.class);

	private static BlockStreamServer server;

	private static int REQUEST_HEADER_TIMEOUT_MS = 10000;

	private static int MAX_AGE_MS = 30000;
	private static int CLEANUP_PERIOD = 30000;

	/**
	 * Get the BlockStreamServer singleton instance.  This is intended for use on 
	 * the server-side only.  The servers TCP port is determined by the {@link ServerPortFactory}
	 * and default interface binding will be performed unless the optional IP interface 
	 * binding option has been specified for the Ghidra Server via the 
	 * <i>java.rmi.server.hostname</i> property setting.
	 * @return BlockStreamServer instance
	 */
	public static synchronized BlockStreamServer getBlockStreamServer() {
		if (server == null) {
			server = new BlockStreamServer();
		}
		return server;
	}

	private Map<Long, BlockStreamRegistration> blockStreamMap = new HashMap<>();

	private long nextStreamID = System.currentTimeMillis();

	private String hostname;
	private volatile boolean running;
	private ServerSocket serverSocket;

	private GTimerMonitor cleanupTimerMonitor;

	/**
	 * Construct a block stream server instance.  
	 */
	private BlockStreamServer() {
		super("BlockStreamServer");
	}

	/**
	 * Determine if server is running
	 * @return true if server is running
	 */
	public synchronized boolean isRunning() {
		return running;
	}

	/**
	 * Get the server port
	 * @return server port, -1 if server not yet started
	 */
	public int getServerPort() {
		return serverSocket != null ? serverSocket.getLocalPort() : -1;
	}

	/**
	 * Get the server remote access hostname
	 * @return hostname or IP address to be used for remote access, null if server not yet started
	 */
	public String getServerHostname() {
		return hostname;
	}

	/**
	 * Get the next available stream ID and auto-increment
	 * @return next stream ID
	 */
	public synchronized long getNextStreamID() {
		return nextStreamID++;
	}

	private enum HandlerConnectionState {
		INIT, READ_HEADER_TIMEOUT, CONNECTED, CLOSED
	}

	private class BlockStreamRegistration {

		final RemoteBlockStreamHandle<?> streamHandle;
		final BlockStream blockStream;

		final long timestamp = System.currentTimeMillis();
		HandlerConnectionState state = HandlerConnectionState.INIT;

		BlockStreamRegistration(RemoteBlockStreamHandle<?> streamHandle, BlockStream blockStream) {
			this.streamHandle = streamHandle;
			this.blockStream = blockStream;
		}
	}

	/**
	 * Register a new block stream to be serviced.  A block stream registration 
	 * will permit the server to associate an in-bound client connection with the 
	 * appropriate block stream.
	 * @param streamHandle the remote block stream handle
	 * @param blockStream the associated block stream data source/sink
	 * @return true if registration succeeded, false if server is not running
	 */
	public boolean registerBlockStream(RemoteBlockStreamHandle<?> streamHandle,
			BlockStream blockStream) {
		synchronized (blockStreamMap) {
			if (!running) {
				return false;
			}
			if (streamHandle == null || blockStream == null) {
				throw new IllegalArgumentException("null argument not permitted");
			}
			long streamID = streamHandle.getStreamID();
			if (!streamHandle.isPending() || blockStreamMap.containsKey(streamID)) {
				throw new IllegalArgumentException("stream handle previously registered/used");
			}

			blockStreamMap.put(streamID, new BlockStreamRegistration(streamHandle, blockStream));
			return true;
		}
	}

	/**
	 * Cleanup unused block stream registrations which are too old
	 * @param cleanupAll if true all requests will be cleaned-up due to server shutdown
	 */
	private void cleanupStaleRequests(boolean cleanupAll) {
		synchronized (blockStreamMap) {
			for (BlockStreamRegistration registration : blockStreamMap.values()) {
				long age = System.currentTimeMillis() - registration.timestamp;
				if (age > MAX_AGE_MS) {
					blockStreamMap.remove(registration.streamHandle.getStreamID());
					try {
						registration.blockStream.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}
	}

	/**
	 * Start this server instance. If the server has already been started
	 * this method will return immediately. 
	 * @param s server socket to be used for accepting connections
	 * @param host remote access hostname to be used by clients
	 * @throws IOException
	 */
	public synchronized void startServer(ServerSocket s, String host) throws IOException {

		if (running) {
			throw new IOException("server already started");
		}

		if (s == null || s.isClosed() || StringUtilities.isAllBlank(host)) {
			throw new IllegalArgumentException("invalid startServer parameters");
		}
		serverSocket = s;
		hostname = host;
		running = true;

		log.info("Starting Block Stream Server...");

		cleanupTimerMonitor = GTimer.scheduleRepeatingRunnable(CLEANUP_PERIOD, CLEANUP_PERIOD,
			() -> cleanupStaleRequests(false));

		start();
	}

	/**
	 * Stop this block stream server instance.
	 */
	public synchronized void stopServer() {
		if (running) {
			running = false;
			cleanupTimerMonitor.cancel();
			cleanupStaleRequests(true);
			try {
				serverSocket.close();
			}
			catch (IOException e) {
				// ignore
			}
			log.info("Shutdown Block Stream Server completed");
			interrupt();
		}
	}

	@Override
	public void run() {

		while (running) {
			Socket socket = null;
			try {
				socket = serverSocket.accept();
				BlockStreamHandler handler = new BlockStreamHandler(socket);
				handler.start();
			}
			catch (InterruptedIOException e) {
				// ignore
			}
			catch (IOException e) {
				if (running) {
					// only log error if server was not shutdown
					log.error("block stream connection failure", e);
				}
			}
			catch (Throwable t) {
				log.error("severe block stream server failure: ", t);
				if (socket != null) {
					try {
						socket.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
			}
		}
	}

	/**
	 * <code>BlockStreamHandler</code> services a block stream request in a dedicated 
	 * thread.  When first started the stream request header will be read from the socket
	 * and the associated registered block stream identified.
	 */
	private class BlockStreamHandler extends Thread {

		private Socket socket;
		private BlockStreamRegistration registration;

		/**
		 * BlockStreamHandler constructor
		 * @param socket accepted/connected socket
		 */
		BlockStreamHandler(Socket socket) {
			super("BlockStreamHandler-" + socket.getInetAddress() + "-" + socket.getPort());
			this.socket = socket;
		}

		@Override
		public void run() {
			boolean success = false;
			try {
				StreamRequest streamRequest = readStreamRequest();

				synchronized (blockStreamMap) {
					registration = blockStreamMap.get(streamRequest.streamID);
					if (registration == null || !registration.streamHandle.isPending()) {
						log.error("unexpected stream connection from " + socket.getInetAddress());
						return;
					}
					if (registration.streamHandle.getAuthenticationToken() != streamRequest.authenticationToken) {
						log.error("unauthorized stream connection from " + socket.getInetAddress());
						return;
					}
					blockStreamMap.remove(streamRequest.streamID);
				}

				registration.state = HandlerConnectionState.CONNECTED;

				// serveBlockStream blocks until transfer complete
				registration.streamHandle.serveBlockStream(socket, registration.blockStream);
				registration.blockStream.close();
				success = true;
			}
			catch (IOException e) {
				if (registration != null &&
					registration.state == HandlerConnectionState.READ_HEADER_TIMEOUT) {
					log.error("stream connection failed from " + socket.getInetAddress() +
						": failed to read stream header");
				}
				else if (!(e instanceof EOFException)) { // silent on closed connection
					log.error("file block stream failed from " + socket.getInetAddress() + ": " +
						e.getMessage());
				}
			}
			finally {
				if (!success && (registration.blockStream instanceof InputBlockStream)) {
					// ensure input stream is closed since it can be terminated by client, 
					// let client handle error if any
					try {
						registration.blockStream.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
				if (!socket.isClosed()) {
					try {
						socket.close();
					}
					catch (IOException e) {
						// ignore
					}
				}
				registration.state = HandlerConnectionState.CLOSED;
			}
		}

		/**
		 * Read the stream request header which must be the first input 
		 * received from the client.
		 * @return StreamRequest data presented by client
		 * @throws IOException
		 */
		private StreamRequest readStreamRequest() throws IOException {

			// Stream request header must be received quickly and processed quickly
			GTimerMonitor requestReadTimer =
				GTimer.scheduleRunnable(REQUEST_HEADER_TIMEOUT_MS, () -> {
					try {
						socket.close();
					}
					catch (IOException e) {
						// ignore
					}
				});

			// read stream connection request info which must be the first
			// content sent from client
			byte[] headerBytes;
			try {
				InputStream in = socket.getInputStream();
				headerBytes = new byte[RemoteBlockStreamHandle.HEADER_LENGTH];
				int index = 0;
				while (index < headerBytes.length) {
					int cnt = in.read(headerBytes, index, headerBytes.length - index);
					if (cnt < 0) {
						throw new SocketException("connection closed by client");
					}
					index += cnt;
				}
			}
			finally {
				requestReadTimer.cancel();
			}

			return RemoteBlockStreamHandle.parseStreamRequestHeader(headerBytes);
		}
	}

}
