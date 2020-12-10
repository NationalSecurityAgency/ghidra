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

import static ghidra.async.AsyncUtils.loop;
import static ghidra.async.AsyncUtils.sequence;

import java.nio.channels.AsynchronousSocketChannel;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import ghidra.async.*;
import ghidra.comm.packet.AsynchronousPacketChannel;
import ghidra.comm.service.AbstractAsyncClientHandler;
import ghidra.dbg.sctl.client.err.SctlIncorrectVersionRequest;
import ghidra.dbg.sctl.dialect.SctlDialect;
import ghidra.dbg.sctl.dialect.SctlNullDialect;
import ghidra.dbg.sctl.err.SctlError;
import ghidra.dbg.sctl.protocol.*;
import ghidra.dbg.sctl.protocol.common.reply.*;
import ghidra.dbg.sctl.protocol.common.request.SctlPingRequest;
import ghidra.dbg.sctl.protocol.common.request.SctlVersionRequest;
import ghidra.dbg.sctl.protocol.consts.Mkind;
import ghidra.dbg.util.HandlerMap;
import ghidra.util.Msg;

/**
 * A base class for SCTL servers to handle a single client
 * 
 * This is a bare-bones base class for handling SCTL clients on the server side. This instantiates
 * the marshaller, creates a handler map, and provides version/dialect negotiation and ping response
 * logic. If any exception is thrown in a handler, it automatically produces a {@code Rerror}
 * response. Throwing a {@code SctlError} provides the given message verbatim. Any other exception
 * will include the exception class name in the transmitted response, and it will log a stacktrace.
 * 
 * This class anticipates supporting a single dialect. If that is not the case, the implementor must
 * override {@link #processVersion(SctlVersionRequest, int)} or provide an alternative handler for
 * {@link SctlVersionRequest}.
 */
public abstract class AbstractSctlClientHandler
		extends AbstractAsyncClientHandler<AbstractSctlServer, AbstractSctlClientHandler> {
	private static final boolean PRINT_STACK_TRACES_FOR_ERROR_REPLIES = true;
	protected final AsynchronousPacketChannel<AbstractSelSctlPacket, AbstractSelSctlPacket> channel;
	private final SctlMarshaller marshaller;
	private SctlDialect dialect = SctlDialect.NULL_DIALECT;

	protected final HandlerMap<AbstractSctlRequest, Integer, CompletableFuture<Void>> handlerMap =
		new HandlerMap<>();

	/**
	 * Create a new SCTL client handler with the given server
	 * 
	 * @param server the server handling the client
	 * @param sock a connection to the client
	 */
	public AbstractSctlClientHandler(AbstractSctlServer server, AsynchronousSocketChannel sock) {
		super(server, sock);
		marshaller = new SctlMarshaller();
		marshaller.setPacketFactory(dialect.getPacketFactory());
		channel = new AsynchronousPacketChannel<>(sock, marshaller);

		defaultHandlers();
	}

	/**
	 * Get the dialects known to the server, in order of preference
	 * 
	 * NOTE: Use {@link LinkedHashSet} to control the order
	 * 
	 * @return the ordered set of known dialects
	 */
	protected abstract Set<SctlDialect> getKnownDialects();

	/**
	 * Choose the dialect for this handler from those offered by the client
	 * 
	 * Ordinarily, every dialect offered by the client is provided in the {@code supported} set. If
	 * another client is connected and completed negotiation, then the set can only contain the
	 * current dialect. If the client does not offer the same dialect, the client will be rejected.
	 * Override {@link #chooseDialect(String)} to change that behavior.
	 * 
	 * By default, this implementation will take the intersection of supported dialects and the set
	 * returned by {@link #getKnownDialects()}, taking the most-preferred dialect. Note that the set
	 * of dialects known to this server is typically a subset of those known to the SCTL framework.
	 * 
	 * @param supported the dialects supported by the client and the SCTL framework
	 * @return the chosen dialect
	 * @throws SctlError if the server cannot support the client
	 */
	protected SctlDialect chooseDialect(Set<SctlDialect> supported) {
		for (SctlDialect preferred : getKnownDialects()) {
			if (supported.contains(preferred)) {
				return preferred;
			}
		}
		throw new SctlError("Server does not support any offered dialects.");
	}

	/**
	 * Choose the dialect for this handler from the version string in the client's request
	 * 
	 * It is preferred that you override {@link #chooseDialect(Set)} or {@link #getKnownDialects()}.
	 * 
	 * @param offered the version string presented by the client, including the ctl version
	 * @return the chosen dialect
	 * @throws SctlError if the server cannot support the client
	 */
	protected SctlDialect chooseDialect(String offered) {
		Set<SctlDialect> supported = SctlVersionInfo.collectSupported(offered);
		SctlDialect curDialect = server.getDialect();
		if (curDialect != SctlDialect.NULL_DIALECT) {
			if (!supported.contains(curDialect)) {
				throw new SctlIncorrectVersionRequest(
					"Client does not support the version active on the bus: " +
						curDialect.getFullVersion());
			}
			supported.clear();
			supported.add(curDialect);
			// Pass it through chooseDialect instead of returning it
			// May not be necessary, but at least gives the implementation a chance
		}
		return chooseDialect(supported);
	}

	/**
	 * Get the chosen dialect, or the {@link SctlNullDialect} if still negotiating
	 * 
	 * @return the current dialect
	 */
	protected SctlDialect getDialect() {
		return dialect;
	}

	/**
	 * Install the basic request handlers
	 * 
	 * The client handler uses the {@link HandlerMap} utility to match each packet type to its
	 * respective handler. This implementation provides handlers for {@link Mkind#Tversion} and
	 * {@code Tping}. More than likely, an implementor should override this method, but call the
	 * superclass's method immediately. The overriding method can then modify the handler map
	 * freely.
	 * 
	 * All handlers have nearly the same signature:
	 * 
	 * <pre>
	 * CompletableFuture<Void> processX(X req, int tag)
	 * </pre>
	 * 
	 * The handler is called upon receiving a request having exactly type {@code X} (not a subtype).
	 * The tag is given as the extra argument. The handler must immediately return (no blocking on
	 * {@code send}) a future which completes when the reply has been sent. Please use
	 * {@link #reply(AsyncLock.Hold, int, SctlPacket)}. This satisfies the requirement to return
	 * immediately, and it ensures all clients receive a copy of the reply.
	 */
	protected void defaultHandlers() {
		handlerMap.put(SctlVersionRequest.class, this::processVersion);
		handlerMap.put(SctlPingRequest.class, this::processPing);
	}

	/**
	 * Upon receiving a {@link Mkind#Tversion} request, negotiate the version for the connection
	 * 
	 * @param req the request
	 * @param tag the tag of the request
	 * @return a future which completes when the {@link Mkind#Rversion} reply has been sent
	 */
	protected CompletableFuture<Void> processVersion(SctlVersionRequest req, int tag) {
		SctlDialect newDialect = chooseDialect(req.version);
		server.setDialect(newDialect);
		marshaller.setPacketFactory(newDialect.getPacketFactory());
		dialect = newDialect;
		return reply(null, tag, new SctlVersionReply(newDialect.getFullVersion()));
	}

	/**
	 * Respond to a {@code Tping} request
	 * 
	 * @param req the request
	 * @param tag the tag of the request
	 * @return a future which completes when the {@link Mkind#Rping} reply has been sent
	 */
	protected CompletableFuture<Void> processPing(SctlPingRequest req, int tag) {
		return reply(null, tag, new SctlPingReply(req.bytes.length));
	}

	/**
	 * Send an error reply for a tag and given throwable
	 * 
	 * Implementors should not call this method directly. Throwing an exception, particularly a
	 * {@link SctlError}, from within a handler will cause the handler to send an error response
	 * using this method.
	 * 
	 * @param tag the tag of the request causing the exception
	 * @param e the error the request caused
	 * @return a future which completes when the {@link Mkind#Rerror} reply has been sent
	 */
	protected CompletableFuture<Void> replyErr(int tag, Throwable e) {
		Throwable t = AsyncUtils.unwrapThrowable(e);
		String msg;
		if (t instanceof SctlError) {
			msg = t.getMessage();
		}
		else {
			if (PRINT_STACK_TRACES_FOR_ERROR_REPLIES) {
				Msg.debug(this, "Error caused by request " + tag, e);
			}
			else {
				Msg.debug(this, "Error caused by request " + tag + ": " + e);
			}
			msg = t.getClass() + ": " + t.getMessage();
		}
		// TODO: Should this subvert the server's sendLock?
		return reply(null, tag, new SctlErrorReply(msg));
	}

	@Override
	protected CompletableFuture<Void> launchAsync() {
		return loop(TypeSpec.VOID, (loop) -> {
			if (sock.isOpen()) {
				channel.read(AbstractSelSctlPacket.class).handle(loop::consume);
			}
			else {
				server.removeHandler(this);
				loop.exit();
			}
		}, TypeSpec.cls(AbstractSelSctlPacket.class), (pkt, loop) -> {
			loop.repeat();
			sequence(TypeSpec.VOID).then((seq) -> {
				server.broadcast(null, pkt, this).handle(seq::next);
			}).then((seq) -> {
				if (pkt.sel instanceof AbstractSctlRequest) {
					handlerMap.handle((AbstractSctlRequest) pkt.sel, pkt.tag).handle(seq::next);
				}
				else {
					throw new SctlError("Client can only send requests.");
				}
			}).finish().exceptionally((e) -> {
				replyErr(pkt.tag, e).exceptionally((ee) -> {
					Msg.error(this, "Could not send error reply: " + ee);
					return null;
				});
				return null;
			});
		});
	}

	/**
	 * Send a reply to a request
	 * 
	 * The reply is broadcast to all connected clients. To ensure that replies are sent in order, a
	 * handler may acquire the server's send lock outside of this method.
	 * 
	 * @param hold a hold on the server's send lock, if applicable, to reenter
	 * @param tag the tag of the request to which this reply corresponds
	 * @param reply the reply to send
	 * @return a future which completes when the reply has been sent
	 */
	protected CompletableFuture<Void> reply(AsyncLock.Hold hold, int tag, AbstractSctlReply reply) {
		AbstractSelSctlPacket pkt = dialect.createSel(tag, reply);
		return server.sendLock.with(TypeSpec.VOID, hold).then((newHold, seq) -> {
			AsyncFence fence = new AsyncFence();
			fence.include(channel.write(pkt));
			fence.include(server.broadcast(newHold, pkt, this));
			fence.ready().handle(seq::nextIgnore);
		}).finish();
	}
}
