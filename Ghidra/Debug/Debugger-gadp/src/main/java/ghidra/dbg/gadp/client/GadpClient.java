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
package ghidra.dbg.gadp.client;

import java.io.EOFException;
import java.io.IOException;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jdom.JDOMException;

import com.google.common.cache.RemovalNotification;
import com.google.protobuf.Message;
import com.google.protobuf.ProtocolStringList;

import ghidra.async.*;
import ghidra.dbg.DebuggerModelClosedReason;
import ghidra.dbg.agent.*;
import ghidra.dbg.agent.AbstractTargetObject.ProxyFactory;
import ghidra.dbg.error.*;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.error.*;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.ObjectCreatedEvent;
import ghidra.dbg.gadp.protocol.Gadp.RootMessage;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.gadp.util.ProtobufOneofByTypeHelper;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.*;
import ghidra.util.*;
import ghidra.util.exception.DuplicateNameException;
import utilities.util.ProxyUtilities;

public class GadpClient extends AbstractDebuggerObjectModel
		implements ProxyFactory<List<Class<? extends TargetObject>>> {

	protected static final int WARN_OUTSTANDING_REQUESTS = 10000;
	// TODO: More sophisticated cache management
	// TODO: Perhaps no cache at all, and rely totally on async notifications
	protected static final int MAX_OUTSTANDING_REQUESTS = Integer.MAX_VALUE;
	protected static final int REQUEST_TIMEOUT_MILLIS = Integer.MAX_VALUE;

	protected static final ProtobufOneofByTypeHelper<Gadp.RootMessage, Gadp.RootMessage.Builder> MSG_HELPER =
		ProtobufOneofByTypeHelper.create(Gadp.RootMessage.getDefaultInstance(),
			Gadp.RootMessage.newBuilder(), "msg");

	protected enum ChannelState {
		INACTIVE {
			@Override
			public boolean isOpen() {
				return false;
			}

			@Override
			public boolean isTerminate() {
				return false;
			}
		},
		NEGOTIATING {
			@Override
			public boolean isOpen() {
				return true;
			}

			@Override
			public boolean isTerminate() {
				return false;
			}
		},
		ACTIVE {
			@Override
			public boolean isOpen() {
				return true;
			}

			@Override
			public boolean isTerminate() {
				return false;
			}
		},
		CLOSED {
			@Override
			public boolean isOpen() {
				return false;
			}

			@Override
			public boolean isTerminate() {
				return true;
			}
		};

		public abstract boolean isOpen();

		public abstract boolean isTerminate();
	}

	/**
	 * For diagnostic purposes, it's useful to keep unanswered requests is an easily-reachable place
	 * 
	 * <p>
	 * When not in release mode, this places the request into the future meant to complete with its
	 * reply. In release mode, the recorded request is left null in order to conserve memory. Thus,
	 * one should never access {@link #request} programmatically, except for diagnostics. The field
	 * is meant to be examined only from a Java debugger.
	 */
	protected static class RequestMemo extends CompletableFuture<Gadp.RootMessage> {
		private static final boolean RECORD_REQUESTS = !SystemUtilities.isInReleaseMode();

		@SuppressWarnings("unused")
		private final RootMessage request;

		public RequestMemo(Gadp.RootMessage request) {
			this.request = RECORD_REQUESTS ? request : null;
		}
	}

	protected static Gadp.RootMessage checkError(Gadp.RootMessage msg) {
		Gadp.ErrorReply error = MSG_HELPER.expect(msg, Gadp.ErrorReply.getDefaultInstance());
		if (error != null) {
			switch (error.getCode()) {
				case EC_NO_INTERFACE:
					throw new DebuggerModelTypeException(error.getMessage());
				case EC_NO_OBJECT:
					throw new DebuggerModelNoSuchPathException(error.getMessage());
				case EC_BAD_ARGUMENT:
					throw new DebuggerIllegalArgumentException(error.getMessage());
				case EC_MEMORY_ACCESS:
					throw new DebuggerMemoryAccessException(error.getMessage());
				case EC_REGISTER_ACCESS:
					throw new DebuggerRegisterAccessException(error.getMessage());
				case EC_BAD_ADDRESS:
					throw new AssertionError(
						"Client implementation sent an invalid address: " + error.getMessage());
				case EC_BAD_REQUEST:
					throw new AssertionError(
						"Client implementation sent an invalid request: " + error.getMessage());
				case UNRECOGNIZED:
					throw new AssertionError(
						"Server replied with an error code unknown to the client: " +
							error.getCodeValue() + ": " + error.getMessage());
				case EC_USER_ERROR:
					throw new DebuggerUserException(error.getMessage());
				case EC_MODEL_ACCESS:
					throw new DebuggerModelAccessException(error.getMessage());
				case EC_UNKNOWN:
					throw new RuntimeException("Unknown: " + error.getMessage());
				case EC_NO_VERSION:
				default:
					throw new GadpErrorException(error.getCode(), error.getMessage());
			}
		}
		return msg;
	}

	protected static <T> T nullForNotExist(Throwable e) {
		e = AsyncUtils.unwrapThrowable(e);
		if (e instanceof DebuggerModelNoSuchPathException) {
			return null;
		}
		return ExceptionUtils.rethrow(e);
	}

	protected static GadpClientTargetObject targetObjectOrNull(Object value) {
		if (value instanceof GadpClientTargetObject) {
			return (GadpClientTargetObject) value;
		}
		return null;
	}

	protected static class GadpAddressFactory extends DefaultAddressFactory {
		protected GadpAddressFactory() {
			super(new AddressSpace[] {
				new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0) });
		}

		@Override
		public synchronized AddressSpace getAddressSpace(String name) {
			AddressSpace space = super.getAddressSpace(name);
			if (space != null) {
				return space;
			}

			space = new GenericAddressSpace(name, 64, AddressSpace.TYPE_RAM, getNumAddressSpaces(),
				true);
			try {
				addAddressSpace(space);
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e);
			}
			return space;
		}
	}

	protected class MessagePairingCache extends AsyncPairingCache<Integer, Gadp.RootMessage> {
		protected final AsyncDebouncer<Void> cacheMonitor =
			new AsyncDebouncer<>(AsyncTimer.DEFAULT_TIMER, 500);

		public MessagePairingCache() {
			super(4, REQUEST_TIMEOUT_MILLIS, MAX_OUTSTANDING_REQUESTS);
			cacheMonitor.addListener(this::cacheSettled);
		}

		@Override
		protected void resultRemoved(RemovalNotification<Integer, Gadp.RootMessage> rn) {
			Msg.error(this, "Received message with unexpected sequence number: " + rn);
		}

		@Override
		public CompletableFuture<RootMessage> waitOn(Integer key,
				Function<Integer, CompletableFuture<RootMessage>> futureFactory) {
			cacheMonitor.contact(null);
			return super.waitOn(key, futureFactory);
		}

		@Override
		protected void promiseRemoved(
				RemovalNotification<Integer, CompletableFuture<Gadp.RootMessage>> rn) {
			if (rn.wasEvicted()) {
				String message = "Command with sequence number " + rn.getKey() +
					" evicted because " + rn.getCause();
				Msg.error(this, message);
				AsyncUtils.FRAMEWORK_EXECUTOR.execute(() -> {
					rn.getValue().completeExceptionally(new TimeoutException(message));
				});
			}
			cacheMonitor.contact(null);
		}

		private void cacheSettled(Void __) {
			int size = getUnpairedPromises().size();
			if (size == 0) {
				Msg.info(this, "Unanswered request cache size has settled to 0. All is well.");
			}
			else {
				Msg.info(this, "Unanswered request cache size has settled to " + size +
					". Chances are something's gone wrong.");
			}
		}
	}

	protected final String description;
	protected final AsynchronousByteChannel byteChannel;
	protected final AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> messageChannel;

	protected AsyncReference<ChannelState, DebuggerModelClosedReason> channelState =
		new AsyncReference<>(ChannelState.INACTIVE);
	protected GadpVersion activeVersion = null;
	protected XmlSchemaContext schemaContext;
	protected TargetObjectSchema rootSchema;

	protected final TriConsumer<ChannelState, ChannelState, DebuggerModelClosedReason> listenerForChannelState =
		this::channelStateChanged;
	protected final MessagePairingCache messageMatcher = new MessagePairingCache();
	protected final AtomicInteger sequencer = new AtomicInteger();

	protected final Map<List<String>, GadpClientTargetObject> modelProxies = new HashMap<>();

	protected final GadpAddressFactory factory = new GadpAddressFactory();

	{
		channelState.addChangeListener(listenerForChannelState);
	}

	public GadpClient(String description, AsynchronousByteChannel channel) {
		this.description = description;
		this.byteChannel = channel;
		this.messageChannel = createMessageChannel(channel);
	}

	@Override
	public SpiTargetObject createProxy(AbstractTargetObject<?> delegate,
			List<Class<? extends TargetObject>> mixins) {
		return ProxyUtilities.composeOnDelegate(GadpClientTargetObject.class,
			(GadpClientTargetObject) delegate, mixins, GadpClientTargetObject.LOOKUP);
	}

	protected AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> createMessageChannel(
			AsynchronousByteChannel channel) {
		return new AsyncProtobufMessageChannel<>(channel);
	}

	@Override
	public String toString() {
		return "<GADP Client: " + description + " (" + channelState.get() + ")>";
	}

	protected void channelStateChanged(ChannelState old, ChannelState set,
			DebuggerModelClosedReason reason) {
		if (old == ChannelState.NEGOTIATING && set == ChannelState.ACTIVE) {
			listeners.fire.modelOpened();
		}
		else if (old == ChannelState.ACTIVE && set == ChannelState.CLOSED) {
			listeners.fire.modelClosed(reason);
			root.invalidateSubtree(root, "GADP Client disconnected");
			messageMatcher.flush(new DebuggerModelTerminatingException("GADP Client disconnected"));
		}
	}

	protected CompletableFuture<Gadp.RootMessage> sendCommand(Message.Builder req) {
		Gadp.RootMessage.Builder root = Gadp.RootMessage.newBuilder();
		MSG_HELPER.set(root, req);
		int seqno = sequencer.getAndIncrement();
		root.setSequence(seqno);
		// Need to get into the matcher before we send
		RootMessage built = root.build();
		CompletableFuture<Gadp.RootMessage> waitOn =
			messageMatcher.waitOn(seqno, k -> new RequestMemo(built));
		if (messageMatcher.getUnpairedPromises().size() > WARN_OUTSTANDING_REQUESTS) {
			Msg.warn(this, "Unanswered request count exceeds " + WARN_OUTSTANDING_REQUESTS +
				"! Chances are something's gone wrong.");
		}

		checkOpen();
		return messageChannel.write(built).thenCompose(__ -> {
			checkOpen();
			return waitOn;
		});
	}

	protected <M extends Message> M require(M example, Gadp.RootMessage msg) {
		M inner = MSG_HELPER.expect(msg, example);
		if (inner == null) {
			throw new GadpMessageException("Reply " + msg + " does not contain expected field " +
				MSG_HELPER.getFieldForTypeOf(example));
		}
		return inner;
	}

	protected <M extends Message> CompletableFuture<M> sendChecked(Message.Builder req,
			M exampleRep) {
		if (channelState.get().isTerminate()) {
			return CompletableFuture.failedFuture(
				new DebuggerModelTerminatingException("GADP Client disconnected"));
		}
		return sendCommand(req)
				.thenApply(msg -> require(exampleRep, checkError(msg)));
		//.thenCompose(msg -> flushEvents().thenApply(__ -> msg));
		// messageMatcher.fulfill happens on clientExecutor already
	}

	protected void receiveLoop() {
		AsyncUtils.loop(TypeSpec.VOID, loop -> {
			if (channelState.get().isTerminate()) {
				loop.exit();
				return;
			}
			messageChannel.read(Gadp.RootMessage::parseFrom).handle(loop::consume);
		}, TypeSpec.cls(Gadp.RootMessage.class), (msg, loop) -> {
			CompletableFuture.runAsync(() -> {
				Gadp.EventNotification notify =
					MSG_HELPER.expect(msg, Gadp.EventNotification.getDefaultInstance());
				if (notify != null) {
					processNotification(notify);
				}
				else {
					messageMatcher.fulfill(msg.getSequence(), msg);
				}
			}, clientExecutor).exceptionally(ex -> {
				Msg.error(this, "Error processing message: ", ex);
				return null;
			});
			loop.repeat(); // All async loop to continue while we process
		}).exceptionally(exc -> {
			exc = AsyncUtils.unwrapThrowable(exc);
			if (exc instanceof NotYetConnectedException) {
				throw new AssertionError("Connect first, please", exc);
			}
			else if (exc instanceof EOFException) {
				Msg.error(this, "Channel has no data remaining");
			}
			else if (exc instanceof ClosedChannelException) {
				Msg.error(this, "Channel is already closed");
			}
			else if (exc instanceof CancelledKeyException) {
				Msg.error(this, "Channel key is cancelled. Probably closed");
			}
			else if (exc instanceof RejectedExecutionException) {
				Msg.trace(this, "Ignoring rejection", exc);
			}
			else {
				Msg.error(this, "Receive failed for an unknown reason", exc);
			}
			channelState.set(ChannelState.CLOSED, DebuggerModelClosedReason.abnormal(exc));
			return null;
		});
	}

	protected void processNotification(Gadp.EventNotification notify) {
		if (!byteChannel.isOpen()) {
			return;
		}
		ProtocolStringList path = notify.getPath().getEList();
		//Msg.debug(this, "Processing notification: " + path + " " + notify.getEvtCase());
		if (notify.hasObjectCreatedEvent()) {
			notify.getObjectCreatedEvent();
			// AbstractTargetObject invokes created event
			createProxy(path, notify.getObjectCreatedEvent());
			return;
		}
		if (notify.hasRootAddedEvent()) {
			if (!path.isEmpty()) {
				Msg.warn(this, "Server gave non-root path for root-added event: " +
					PathUtils.toString(path));
			}
			synchronized (lock) {
				addModelRoot(getProxy(List.of(), true));
			}
			return;
		}
		GadpClientTargetObject obj = getProxy(path, true);
		if (obj == null) {
			return; // Error already logged
		}
		obj.getDelegate().handleEvent(notify);
	}

	@Override
	public String getBrief() {
		return "GADP@" + Integer.toHexString(System.identityHashCode(this)) + " " + description;
	}

	public CompletableFuture<Void> connect() {
		Gadp.ConnectRequest.Builder req = GadpVersion.makeRequest();
		if (channelState.get() != ChannelState.INACTIVE) {
			throw new GadpIllegalStateException(
				"Client has already connected or started connecting");
		}
		Msg.trace(this, "Connecting");

		channelState.set(ChannelState.NEGOTIATING, null);

		AsyncFence fence = new AsyncFence();
		fence.include(sendCommand(req).thenAccept(msg -> {
			Gadp.ConnectReply rep =
				require(Gadp.ConnectReply.getDefaultInstance(), checkError(msg));
			GadpVersion version = GadpVersion.getByName(rep.getVersion());
			synchronized (this) {
				activeVersion = version;
				try {
					schemaContext = XmlSchemaContext.deserialize(rep.getSchemaContext());
				}
				catch (JDOMException e) {
					throw new GadpMessageException("Invalid schema context XML", e);
				}
				rootSchema = schemaContext.getSchema(schemaContext.name(rep.getRootSchema()));
			}
			channelState.set(ChannelState.ACTIVE, null);
			// launches in background in parallel, with its own error reporting
			// Thus, do not compose
			receiveLoop();
		}));
		/**
		 * receiveLoop is not yet running, so receive exactly the version reply in parallel.
		 * Otherwise, the above sendCommand can never complete.
		 */
		fence.include(messageChannel.read(Gadp.RootMessage::parseFrom).thenAccept(msg -> {
			messageMatcher.fulfill(msg.getSequence(), msg);
		}));
		return fence.ready();
	}

	@Override
	public CompletableFuture<Void> close() {
		try {
			messageChannel.close();
			channelState.set(ChannelState.CLOSED, DebuggerModelClosedReason.normal());
			return super.close();
		}
		catch (RejectedExecutionException e) {
			reportError(this, "Client already closed", e);
			return AsyncUtils.NIL;
		}
		catch (IOException e) {
			return CompletableFuture.failedFuture(e);
		}
	}

	protected void checkOpen() {
		if (!channelState.get().isOpen()) {
			throw new GadpIllegalStateException("Channel is not open");
		}
	}

	@Override
	public boolean isAlive() {
		return channelState.get() == ChannelState.ACTIVE;
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		return rootSchema;
	}

	@Override
	public CompletableFuture<Void> ping(String content) {
		Gadp.PingRequest.Builder req = Gadp.PingRequest.newBuilder().setContent(content);
		return sendChecked(req, Gadp.PingReply.getDefaultInstance()).thenAccept(rep -> {
			if (!content.equals(rep.getContent())) {
				throw new GadpMessageException(
					"Data in ping was corrupt: req=" + req + ",rep=" + rep);
			}
		});
	}

	protected GadpClientTargetObject getProxy(List<String> path, boolean internal) {
		synchronized (lock) {
			GadpClientTargetObject proxy = modelProxies.get(path);
			if (proxy == null && internal) {
				Msg.error(this,
					"Server referred to non-existent object at path: " + PathUtils.toString(path));
			}
			return proxy;
		}
	}

	protected GadpClientTargetObject createProxy(List<String> path, ObjectCreatedEvent evt) {
		synchronized (lock) {
			if (modelProxies.containsKey(path)) {
				Msg.error(this, "Agent announced creation of an already-existing object: " +
					PathUtils.toString(path));
				return modelProxies.get(path);
			}
			List<String> parentPath = PathUtils.parent(path);
			GadpClientTargetObject parent;
			if (parentPath == null) {
				parent = null;
			}
			else {
				parent = getProxy(parentPath, true);
				if (parent == null) {
					Msg.error(this, "Got object's created event before its parent's: " +
						PathUtils.toString(path));
				}
			}
			GadpClientTargetObject proxy = DelegateGadpClientTargetObject.makeModelProxy(this,
				parent, PathUtils.getKey(path), evt.getTypeHint(), evt.getInterfaceList());
			modelProxies.put(path, proxy);
			return proxy;
		}
	}

	protected void removeProxy(List<String> path, String reason) {
		synchronized (lock) {
			modelProxies.remove(path);
		}
	}

	@Override
	public AddressFactory getAddressFactory() {
		return factory;
	}

	@Override
	public TargetObject getModelObject(List<String> path) {
		return getProxy(path, false);
	}

	@Override
	public void invalidateAllLocalCaches() {
		List<GadpClientTargetObject> copy;
		synchronized (lock) {
			copy = List.copyOf(modelProxies.values());
		}
		for (GadpClientTargetObject proxy : copy) {
			proxy.getDelegate().doClearCaches();
		}
	}
}
