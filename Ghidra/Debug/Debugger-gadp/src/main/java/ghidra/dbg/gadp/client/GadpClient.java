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
import java.lang.ref.Cleaner;
import java.nio.channels.*;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.common.cache.RemovalNotification;
import com.google.protobuf.Message;
import com.google.protobuf.ProtocolStringList;

import ghidra.async.*;
import ghidra.dbg.*;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.*;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.error.*;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.*;
import ghidra.dbg.gadp.util.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetObject.TargetUpdateMode;
import ghidra.dbg.util.PathUtils;
import ghidra.dbg.util.PathUtils.PathComparator;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.util.*;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.datastruct.WeakValueTreeMap;
import ghidra.util.exception.DuplicateNameException;

public class GadpClient implements DebuggerObjectModel {
	protected static final Cleaner CLEANER = Cleaner.create();

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
				case NO_INTERFACE:
					throw new DebuggerModelTypeException(error.getMessage());
				case NO_OBJECT:
					throw new DebuggerModelNoSuchPathException(error.getMessage());
				case BAD_ARGUMENT:
					throw new DebuggerIllegalArgumentException(error.getMessage());
				case MEMORY_ACCESS:
					throw new DebuggerMemoryAccessException(error.getMessage());
				case REGISTER_ACCESS:
					throw new DebuggerRegisterAccessException(error.getMessage());
				case BAD_ADDRESS:
					throw new AssertionError(
						"Client implementation sent an invalid address: " + error.getMessage());
				case BAD_REQUEST:
					throw new AssertionError(
						"Client implementation sent an invalid request: " + error.getMessage());
				case UNRECOGNIZED:
					throw new AssertionError(
						"Server replied with an error code unknown to the client: " +
							error.getCodeValue() + ": " + error.getMessage());
				case USER_ERROR:
					throw new DebuggerUserException(error.getMessage());
				case MODEL_ACCESS:
					throw new DebuggerModelAccessException(error.getMessage());
				case UNKNOWN:
					throw new RuntimeException("Unknown: " + error.getMessage());
				case NO_VERSION:
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
	protected final AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> messageChannel;

	protected AsyncReference<ChannelState, DebuggerModelClosedReason> channelState =
		new AsyncReference<>(ChannelState.INACTIVE);
	protected GadpVersion activeVersion = null;

	protected final ListenerSet<DebuggerModelListener> listenersClient =
		new ListenerSet<>(DebuggerModelListener.class);
	protected final TriConsumer<ChannelState, ChannelState, DebuggerModelClosedReason> listenerForChannelState =
		this::channelStateChanged;
	protected final MessagePairingCache messageMatcher = new MessagePairingCache();
	protected final AtomicInteger sequencer = new AtomicInteger();

	protected final NavigableMap<List<String>, GadpClientTargetObject> modelProxies =
		new WeakValueTreeMap<>(PathComparator.KEYED);

	/**
	 * Forget all values and rely on getCachedValue instead. This lazy map will just de-dup pending
	 * requests. Once received, the behavior depends on what we know about the parent object. If
	 * nothing is known about the parent object, we assume we cannot cache.
	 */
	protected final AsyncLazyMap<List<String>, Object> valueRequests =
		new AsyncLazyMap<>(new HashMap<>(), p -> doRequestValue(p, false));
	protected final AsyncLazyMap<List<String>, GadpClientTargetObject> attrsRequests =
		new AsyncLazyMap<>(new HashMap<>(), p -> doRequestAttributes(p, false));
	protected final AsyncLazyMap<List<String>, GadpClientTargetObject> elemsRequests =
		new AsyncLazyMap<>(new HashMap<>(), p -> doRequestElements(p, false));

	protected final GadpAddressFactory factory = new GadpAddressFactory();

	{
		channelState.addChangeListener(listenerForChannelState);

		valueRequests.forgetValues((p, v) -> true);
		elemsRequests.forgetValues(this::forgetElementsRequests);
		attrsRequests.forgetValues(this::forgetAttributesRequests);
	}

	public GadpClient(String description, AsynchronousByteChannel channel) {
		this.description = description;
		this.messageChannel = createMessageChannel(channel);
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
			listenersClient.fire.modelOpened();
		}
		else if (old == ChannelState.ACTIVE && set == ChannelState.CLOSED) {
			listenersClient.fire.modelClosed(reason);
			List<GadpClientTargetObject> copy;
			synchronized (modelProxies) {
				copy = List.copyOf(modelProxies.values());
			}
			for (GadpClientTargetObject proxy : copy) {
				proxy.getDelegate().doInvalidate("GADP Client disconnected");
			}
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
		return sendCommand(req).thenApply(msg -> require(exampleRep, checkError(msg)));
	}

	protected void receiveLoop() {
		AsyncUtils.loop(TypeSpec.VOID, loop -> {
			if (channelState.get().isTerminate()) {
				loop.exit();
				return;
			}
			messageChannel.read(Gadp.RootMessage::parseFrom).handle(loop::consume);
		}, TypeSpec.cls(Gadp.RootMessage.class), (msg, loop) -> {
			loop.repeat(); // All async loop to continue while we process

			try {
				Gadp.EventNotification notify =
					MSG_HELPER.expect(msg, Gadp.EventNotification.getDefaultInstance());
				if (notify != null) {
					processNotification(notify);
				}
				else {
					messageMatcher.fulfill(msg.getSequence(), msg);
				}
			}
			catch (Throwable e) {
				Msg.error(this, "Error processing message: " + msg, e);
			}
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
			else {
				Msg.error(this, "Receive failed for an unknown reason", exc);
			}
			channelState.set(ChannelState.CLOSED, DebuggerModelClosedReason.abnormal(exc));
			return null;
		});
	}

	protected void processNotification(Gadp.EventNotification notify) {
		ProtocolStringList path = notify.getPath().getEList();
		GadpClientTargetObject obj = getCachedProxy(path);
		if (obj == null) {
			if (!hasPendingRequest(path)) {
				/**
				 * For pending, I guess we just miss the event. NB: If it was a model event, then
				 * the pending subscribe reply ought to already reflect the update we're ignoring
				 * here.
				 */
				Msg.error(this, "Server sent notification for non-cached object: " + notify);
			}
			return;
		}
		obj.getDelegate().handleEvent(notify);
	}

	@Override
	public String getBrief() {
		return description + " via GADP (" + channelState.get().name().toLowerCase() + ")";
	}

	@Override
	public void addModelListener(DebuggerModelListener listener) {
		listenersClient.add(listener);
	}

	@Override
	public void removeModelListener(DebuggerModelListener listener) {
		listenersClient.remove(listener);
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
	public CompletableFuture<Void> ping(String content) {
		Gadp.PingRequest.Builder req = Gadp.PingRequest.newBuilder().setContent(content);
		return sendChecked(req, Gadp.PingReply.getDefaultInstance()).thenAccept(rep -> {
			if (!content.equals(rep.getContent())) {
				throw new GadpMessageException(
					"Data in ping was corrupt: req=" + req + ",rep=" + rep);
			}
		});
	}

	protected GadpClientTargetObject getCachedProxy(List<String> path) {
		synchronized (modelProxies) {
			return modelProxies.get(path);
		}
	}

	protected GadpClientTargetObject removeCachedProxy(List<String> path) {
		synchronized (modelProxies) {
			return modelProxies.remove(path);
		}
	}

	/**
	 * Check for a cached value
	 * 
	 * This first checks if the given path is a cached object and returns it if so. Otherwise, it
	 * checks if the parent is cached and, if so, examines its cached children.
	 * 
	 * Note, if {@code null} is returned, the cache has no knowledge of the given path; the server
	 * must be queried. If the returned optional has no value, the cache knows the path does not
	 * exist.
	 * 
	 * @param path the path
	 * @return an optional value, or {@code null} if not cached
	 */
	protected Optional<Object> getCachedValue(List<String> path) {
		GadpClientTargetObject proxy = getCachedProxy(path);
		if (proxy != null) {
			return Optional.of(proxy);
		}
		List<String> parentPath = PathUtils.parent(path);
		if (parentPath == null) {
			return null;
		}
		GadpClientTargetObject parent = getCachedProxy(parentPath);
		if (parent == null) {
			return null;
		}
		Optional<Object> val = parent.getDelegate().cachedChild(PathUtils.getKey(path));
		if (val == null) {
			return null;
		}
		if (val.isEmpty()) {
			if (PathUtils.isInvocation(PathUtils.getKey(path))) {
				return null;
			}
			return val;
		}
		Object v = val.get();
		/**
		 * NOTE: val should not be a TargetObject, otherwise it should have hit via
		 * getCachedProxy(path). If this is a TargetObject, it's because the proxy was created
		 * between then and the call to cachedChild -- possible due to a race condition. In that
		 * case, it seems harmless to just return it anyway.
		 */
		if (v instanceof TargetObject) {
			return val;
		}
		if (!(v instanceof TargetObjectRef)) {
			return val;
		}
		TargetObjectRef r = (TargetObjectRef) v;
		if (path.equals(r.getPath())) {
			// An TargetObject is expected, but we only have the placeholder cached
			return null;
		}
		// else a link, which we are not required to fetch
		return val;
	}

	protected void cacheInParent(List<String> path, GadpClientTargetObject proxy) {
		List<String> parentPath = PathUtils.parent(path);
		if (parentPath == null) {
			return;
		}
		GadpClientTargetObject parent = modelProxies.get(parentPath);
		if (parent == null) {
			return;
		}
		parent.getDelegate().putCachedProxy(PathUtils.getKey(path), proxy);
	}

	@Internal
	public GadpClientTargetObject getProxyForInfo(ModelObjectInfo info) {
		synchronized (modelProxies) {
			return modelProxies.computeIfAbsent(info.getPath().getEList(), path -> {
				GadpClientTargetObject proxy = DelegateGadpClientTargetObject.makeModelProxy(this,
					path, info.getTypeHint(), info.getInterfaceList());
				cacheInParent(path, proxy);
				return proxy;
			});
		}
	}

	@Internal
	public TargetObjectRef getProxyOrStub(List<String> path) {
		GadpClientTargetObject cached = getCachedProxy(path);
		if (cached != null) {
			return cached;
		}
		return new GadpClientTargetObjectStub(this, path);
	}

	protected CompletableFuture<Void> unsubscribe(List<String> path) {
		AsyncFence fence = new AsyncFence();
		cleanRequests(path);
		fence.include(sendChecked(
			Gadp.SubscribeRequest.newBuilder()
					.setPath(GadpValueUtils.makePath(path))
					.setSubscribe(false),
			Gadp.SubscribeReply.getDefaultInstance()));
		return fence.ready();
	}

	protected void invalidateSubtree(List<String> path, String reason) {
		List<List<String>> pathsToInvalidate = new ArrayList<>();
		List<GadpClientTargetObject> proxiesToInvalidate;
		synchronized (modelProxies) {
			// keySet is the only one which isn't a copy.
			// TODO: Would rather iterate entries when AbstractWeakValueMap is fixed
			for (List<String> succPath : modelProxies.tailMap(path, true).keySet()) {
				if (!PathUtils.isAncestor(path, succPath)) {
					break;
				}
				pathsToInvalidate.add(succPath);
			}
			proxiesToInvalidate =
				pathsToInvalidate.stream().map(modelProxies::remove).collect(Collectors.toList());
		}
		for (GadpClientTargetObject proxy : proxiesToInvalidate) {
			proxy.getDelegate().doInvalidate(reason);
		}
	}

	public boolean hasPendingRequest(List<String> path) {
		return valueRequests.containsKey(path) || attrsRequests.containsKey(path) ||
			elemsRequests.containsKey(path);
	}

	public boolean hasPendingAttributes(List<String> path) {
		return attrsRequests.containsKey(path);
	}

	public boolean hasPendingElements(List<String> path) {
		return elemsRequests.containsKey(path);
	}

	protected void cleanRequests(List<String> path) {
		valueRequests.forget(path);
		attrsRequests.forget(path);
		elemsRequests.forget(path);
	}

	@Override
	public CompletableFuture<? extends TargetObject> fetchModelRoot() {
		return fetchModelObject(List.of());
	}

	protected CompletableFuture<Object> doRequestValueWithObjectInfo(
			List<String> path, boolean refresh,
			boolean fetchElements, boolean refreshElements,
			boolean fetchAttributes, boolean refreshAttributes) {
		CompletableFuture<SubscribeReply> reply = sendChecked(Gadp.SubscribeRequest.newBuilder()
				.setPath(GadpValueUtils.makePath(path))
				.setSubscribe(true)
				.setRefresh(refresh)
				.setFetchElements(fetchElements)
				.setRefreshElements(refreshElements)
				.setFetchAttributes(fetchAttributes)
				.setRefreshAttributes(refreshAttributes),
			Gadp.SubscribeReply.getDefaultInstance());
		return reply.thenApplyAsync(rep -> { // Async to avoid processing info with a lock
			Gadp.Value value = rep.getValue();
			if (value.getSpecCase() == Gadp.Value.SpecCase.OBJECT_STUB) {
				Msg.error(this, "Server responded to object request with a stub!");
				return null;
			}
			if (value.getSpecCase() != Gadp.Value.SpecCase.OBJECT_INFO) {
				return GadpValueUtils.getValue(this, path, value);
			}
			Gadp.ModelObjectInfo info = value.getObjectInfo();
			GadpClientTargetObject proxy = getProxyForInfo(info);
			proxy.getDelegate().updateWithInfo(info);
			return proxy;
		}, AsyncUtils.FRAMEWORK_EXECUTOR);
	}

	protected CompletableFuture<GadpClientTargetObject> doRequestElements(List<String> path,
			boolean refresh) {
		return doRequestValueWithObjectInfo(path, false, true, refresh, false, false)
				.thenApply(GadpClient::targetObjectOrNull);
	}

	protected CompletableFuture<GadpClientTargetObject> doRequestAttributes(List<String> path,
			boolean refresh) {
		return doRequestValueWithObjectInfo(path, false, false, false, true, refresh)
				.thenApply(GadpClient::targetObjectOrNull);
	}

	protected boolean forgetElementsRequests(List<String> path, GadpClientTargetObject proxy) {
		return proxy == null || !proxy.isValid() ||
			proxy.getUpdateMode() == TargetUpdateMode.SOLICITED;
	}

	protected CompletableFuture<GadpClientTargetObject> checkProcessedElemsReply(List<String> path,
			boolean refresh) {
		if (refresh) { // NB: the map pre-tests the forget condition, too
			elemsRequests.forget(path);
			return elemsRequests.get(path, p -> doRequestElements(p, refresh));
		}
		return elemsRequests.get(path);
	}

	@Override
	public CompletableFuture<? extends Map<String, ? extends TargetObjectRef>> fetchObjectElements(
			List<String> path, boolean refresh) {
		CompletableFuture<GadpClientTargetObject> processedReply =
			checkProcessedElemsReply(path, refresh);
		return processedReply.thenApply(proxy -> {
			if (proxy == null) { // The path doesn't exist, so return null, per the docs
				return null;
			}
			return proxy.getCachedElements();
		}).exceptionally(GadpClient::nullForNotExist);
	}

	protected boolean forgetAttributesRequests(List<String> path, GadpClientTargetObject proxy) {
		return proxy == null || !proxy.isValid();
	}

	protected CompletableFuture<GadpClientTargetObject> checkProcessedAttrsReply(List<String> path,
			boolean refresh) {
		if (refresh) {
			attrsRequests.forget(path);
			return attrsRequests.get(path, p -> doRequestAttributes(p, refresh));
		}
		return attrsRequests.get(path);
	}

	@Override
	public CompletableFuture<? extends Map<String, ?>> fetchObjectAttributes(List<String> path,
			boolean refresh) {
		CompletableFuture<GadpClientTargetObject> processedReply =
			checkProcessedAttrsReply(path, refresh);
		return processedReply.thenApply(proxy -> {
			if (proxy == null) { // The path doesn't exist, so return null, per the docs
				return null;
			}
			return proxy.getCachedAttributes();
		}).exceptionally(GadpClient::nullForNotExist);
	}

	@Override
	public CompletableFuture<?> fetchModelValue(List<String> path, boolean refresh) {
		/**
		 * NB. Not sure there's value in checking for element/attribute requests on the parent. May
		 * cull some requests, but the logic could get complicated. E.g., if we wait for it to
		 * complete, and it comes back a TargetObjectRef, well, we have to fetch anyway. For
		 * attributes, we'd also have to consider the case where it's absent, because it's a method
		 * invocation.
		 */
		if (!refresh) {
			Optional<Object> cached = getCachedValue(path);
			if (cached != null) {
				Object val = cached.orElse(null);
				if (!(val instanceof TargetObjectRef)) {
					return CompletableFuture.completedFuture(val);
				}
				TargetObjectRef ref = (TargetObjectRef) val;
				TargetObject obj = GadpValueUtils.getTargetObjectNonLink(path, ref);
				if (obj != null) {
					return CompletableFuture.completedFuture(val);
				}
			}
		}
		return valueRequests.get(path, p -> doRequestValue(p, refresh))
				.exceptionally(GadpClient::nullForNotExist);
	}

	@Override
	public CompletableFuture<?> fetchModelValue(List<String> path) {
		return fetchModelValue(path, false);
	}

	protected CompletableFuture<Object> doRequestValue(List<String> path, boolean refresh) {
		return doRequestValueWithObjectInfo(path, refresh, false, false, false, false);
	}

	@Override
	public AddressFactory getAddressFactory() {
		return factory;
	}

	@Override
	public TargetObjectRef createRef(List<String> path) {
		return getProxyOrStub(path);
	}

	@Override
	public void invalidateAllLocalCaches() {
		List<GadpClientTargetObject> copy;
		synchronized (modelProxies) {
			copy = List.copyOf(modelProxies.values());
		}
		for (GadpClientTargetObject proxy : copy) {
			proxy.getDelegate().doClearCaches();
		}
	}
}
