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
package ghidra.dbg.sctl.server;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import ghidra.async.AsyncLock;
import ghidra.async.TypeSpec;
import ghidra.comm.service.AbstractAsyncServer;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.protocol.AbstractSelSctlPacket;
import ghidra.dbg.sctl.protocol.common.notify.AbstractSctlEventNotification;
import ghidra.dbg.sctl.protocol.common.notify.SctlEventNotify;
import ghidra.dbg.sctl.protocol.consts.Evkind;
import ghidra.util.Msg;

/**
 * A base class for SCTL servers
 * 
 * This class and the base {@link AbstractSctlClientHandler} implement all of the socket operations,
 * message parsing, message forwarding, etc., of a SCTL-bus-compliant server. Implementors need only
 * override {@link #newHandler(AsynchronousSocketChannel)} to provide a concrete handler. The
 * handler implementation is where all of the message processing occurs.
 */
public abstract class AbstractSctlServer
		extends AbstractAsyncServer<AbstractSctlServer, AbstractSctlClientHandler> {
	private SctlDialect activeDialect = SctlDialect.NULL_DIALECT;

	public final AsyncLock sendLock = new AsyncLock();

	/**
	 * Start a SCTL server bound to the given address
	 * 
	 * @param addr the socket address to bind
	 * @throws IOException if the socket bind or listen fails
	 */
	public AbstractSctlServer(SocketAddress addr) throws IOException {
		super(addr);
	}

	@Override
	protected void removeHandler(AbstractSctlClientHandler handler) {
		super.removeHandler(handler);
		if (handlers.isEmpty()) {
			// Allow another client to freely re-negotiate.
			activeDialect = SctlDialect.NULL_DIALECT;
		}
	}

	protected void setDialect(SctlDialect dialect) {
		if (activeDialect != SctlDialect.NULL_DIALECT && dialect != activeDialect) {
			throw new IllegalStateException("Server cannot speak multiple dialects on the bus");
		}
		activeDialect = dialect;
	}

	protected SctlDialect getDialect() {
		return activeDialect;
	}

	@Override
	protected boolean checkAcceptable(AsynchronousSocketChannel sock) {
		if (!handlers.isEmpty() && activeDialect != SctlDialect.NULL_DIALECT &&
			!activeDialect.isBusSupported()) {
			Msg.error(this, "Rejected connection. Current client is not bus aware.");
			return false;
		}
		return true;
	}

	protected CompletableFuture<Integer> sendTo(AbstractSctlClientHandler to,
			AbstractSelSctlPacket pkt) {
		return to.channel.write(pkt).exceptionally((exc) -> {
			if (exc instanceof CompletionException) {
				exc = exc.getCause();
			}
			if (exc instanceof IOException) {
				Msg.info(this, "Send failed: " + exc.getMessage() +
					". Probably the client closed the connection");
				removeHandler(to);
			}
			else {
				Msg.error(this, "Send failed for unknown reason", exc);
			}
			return null;
		});
	}

	/**
	 * Broadcast a message to all clients except an optional source
	 * 
	 * To ensure replies are sent in order, a handler may acquire the server's send lock outside of
	 * this method.
	 * 
	 * @param hold a hold on the server's send lock, if applicable, to reenter
	 * @param pkt the packet to broadcast
	 * @param from the source client, if applicable, to exclude from the broadcast
	 * @return a future which completes when the packet has been sent
	 */
	protected CompletableFuture<Void> broadcast(AsyncLock.Hold hold, AbstractSelSctlPacket pkt,
			AbstractSctlClientHandler from) {
		return sendLock.with(TypeSpec.VOID, hold).then((newHold, seq) -> allHandlers(to -> {
			if (to == from) {
				return null;
			}
			return sendTo(to, pkt);
		}).handle(seq::exit)).finish();
	}

	/**
	 * Broadcast a notification to all clients about a thread event
	 * 
	 * @param hold a hold on the server's send lock, if applicable, to reenter
	 * @param ctlid the CTLID of the thread producing the event
	 * @param notification the notification about the event
	 * @return a future which completes when the notification has been sent
	 */
	public CompletableFuture<Void> notify(AsyncLock.Hold hold, long ctlid,
			AbstractSctlEventNotification notification) {
		return notify(hold, ctlid, notification, BitmaskSet.of());
	}

	/**
	 * Broadcast a notification with extra flags to all clients about a thread event
	 * 
	 * @param hold a hold on the server's send lock, if applicable, to reenter
	 * @param ctlid the CTLID of the thread producing the event
	 * @param notification the notification about the event
	 * @param addFlags the extra (non-event) flags to include
	 * @return a future which completes when the notification has been sent
	 */
	public CompletableFuture<Void> notify(AsyncLock.Hold hold, long ctlid,
			AbstractSctlEventNotification notification, BitmaskSet<Evkind> addFlags) {
		return broadcast(hold,
			activeDialect.createSel(0, new SctlEventNotify(ctlid, notification, addFlags)), null);
	}
}
