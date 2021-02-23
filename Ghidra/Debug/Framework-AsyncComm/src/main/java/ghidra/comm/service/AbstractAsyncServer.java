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
package ghidra.comm.service;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.*;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.*;
import java.util.function.Function;

import ghidra.async.*;
import ghidra.util.Msg;

public abstract class AbstractAsyncServer<S extends AbstractAsyncServer<S, H>, H extends AbstractAsyncClientHandler<S, H>> {
	// One thread for all clients... OK since generally only one is connected.
	private final AsynchronousChannelGroup group =
		AsynchronousChannelGroup.withThreadPool(Executors.newSingleThreadExecutor());
	private final AsynchronousServerSocketChannel ssock;
	//private final SocketAddress addr;

	protected final Set<H> handlers = Collections.newSetFromMap(new ConcurrentHashMap<>());

	public AbstractAsyncServer(SocketAddress addr) throws IOException {
		//this.addr = addr;
		ssock = AsynchronousServerSocketChannel.open(group);
		ssock.bind(addr);
	}

	private CompletableFuture<AsynchronousSocketChannel> accept() {
		return AsyncUtils.completable(TypeSpec.cls(AsynchronousSocketChannel.class), ssock::accept);
	}

	protected abstract boolean checkAcceptable(AsynchronousSocketChannel sock);

	/**
	 * Create a new handler for the given incoming client connection
	 * 
	 * @param sock the new client connection
	 * @return a handler for the client
	 */
	protected abstract H newHandler(AsynchronousSocketChannel sock);

	protected void removeHandler(H handler) {
		handlers.remove(handler);
	}

	public CompletableFuture<Void> launchAsyncService() {
		return AsyncUtils.loop(TypeSpec.VOID, loop -> {
			if (ssock.isOpen()) {
				accept().handle(loop::consume);
			}
			else {
				loop.exit();
			}
		}, TypeSpec.cls(AsynchronousSocketChannel.class), (sock, loop) -> {
			loop.repeat();
			if (!checkAcceptable(sock)) {
				try {
					sock.close();
				}
				catch (IOException e) {
					Msg.error(this, "Failed to close rejected connection", e);
				}
			}
			else {
				H handler = newHandler(sock);
				handlers.add(handler);
				handler.launchAsync().thenAccept(v -> {
					removeHandler(handler);
				}).exceptionally(e -> {
					Msg.error("Client handler terminated unexpectedly", e);
					removeHandler(handler);
					return null;
				});
			}
		});
	}

	public SocketAddress getLocalAddress() {
		try {
			return ssock.getLocalAddress();
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Close the server socket and all current client connections
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	public void terminate() throws IOException {
		IOException err = null;
		try {
			ssock.close();
		}
		catch (IOException e) {
			err = e;
		}
		for (H h : handlers) {
			try {
				h.close();
			}
			catch (IOException e) {
				if (err == null) {
					err = e;
				}
			}
		}
		group.shutdown();
		if (err != null) {
			throw err;
		}
	}

	protected CompletableFuture<Void> allHandlers(Function<H, CompletableFuture<?>> action) {
		AsyncFence fence = new AsyncFence();
		for (H h : handlers) {
			CompletableFuture<?> future = action.apply(h);
			if (future != null) {
				fence.include(future);
			}
		}
		return fence.ready();
	}
}
