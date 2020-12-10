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
package ghidra.dbg.gadp.server;

import java.nio.channels.AsynchronousSocketChannel;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.google.protobuf.ByteString;
import com.google.protobuf.ProtocolStringList;

import ghidra.async.*;
import ghidra.comm.service.AbstractAsyncClientHandler;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.*;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.client.GadpClientTargetAttachable;
import ghidra.dbg.gadp.error.GadpErrorException;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.ErrorCode;
import ghidra.dbg.gadp.protocol.Gadp.ObjectInvalidateEvent;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.gadp.util.GadpValueUtils;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetAccessConditioned.TargetAccessibilityListener;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointListener;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventScopeListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionStateListener;
import ghidra.dbg.target.TargetFocusScope.TargetFocusScopeListener;
import ghidra.dbg.target.TargetInterpreter.TargetInterpreterListener;
import ghidra.dbg.target.TargetMemory.TargetMemoryListener;
import ghidra.dbg.target.TargetObject.TargetObjectListener;
import ghidra.dbg.target.TargetRegisterBank.TargetRegisterBankListener;
import ghidra.dbg.util.CollectionUtils.Delta;
import ghidra.dbg.util.PathUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;

public class GadpClientHandler
		extends AbstractAsyncClientHandler<AbstractGadpServer, GadpClientHandler> {
	protected static final boolean LOG_ERROR_REPLY_STACKS = false;

	protected static class UpdateSuppression {
		int attributesCount = 0;
		int elementsCount = 0;

		boolean isEmpty() {
			return attributesCount == 0 && elementsCount == 0;
		}

		void incrementAttributes() {
			attributesCount++;
		}

		void decrementAttributes() {
			assert attributesCount > 0;
			attributesCount--;
		}

		void incrementElements() {
			elementsCount++;
		}

		void decrementElements() {
			assert elementsCount > 0;
			elementsCount--;
		}
	}

	protected class ListenerForEvents
			implements TargetObjectListener, TargetAccessibilityListener, TargetBreakpointListener,
			TargetEventScopeListener, TargetExecutionStateListener, TargetFocusScopeListener,
			TargetInterpreterListener, TargetMemoryListener, TargetRegisterBankListener {

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			// TODO: Can elements and attributes be combined into one message?
			sendDelta(parent, Delta.empty(), Delta.create(removed, added))
					.exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
			// TODO: Can elements and attributes be combined into one message?
			sendDelta(parent, Delta.create(removed, added), Delta.empty())
					.exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void invalidated(TargetObject object, String reason) {
			if (!unsubscribeSubtree(object)) {
				return;
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(object.getPath()))
							.setObjectInvalidateEvent(
								ObjectInvalidateEvent.newBuilder().setReason(reason)))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void consoleOutput(TargetObject console, Channel c, byte[] data) {
			if (c == null || console == null) {
				Msg.warn(this, "Why is console or channel null in consoleOutput callback?");
				return;
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(console.getPath()))
							.setConsoleOutputEvent(Gadp.ConsoleOutputEvent.newBuilder()
									.setChannel(c.ordinal())
									.setData(ByteString.copyFrom(data))))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void consoleOutput(TargetObject console, Channel c, String out) {
			consoleOutput(console, c, out.getBytes(TargetConsole.CHARSET));
		}

		@Override
		public void breakpointHit(TargetBreakpointContainer<?> container, TargetObjectRef trapped,
				TypedTargetObjectRef<? extends TargetStackFrame<?>> frame,
				TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> spec,
				TypedTargetObjectRef<? extends TargetBreakpointLocation<?>> breakpoint) {
			Gadp.BreakHitEvent.Builder evt = Gadp.BreakHitEvent.newBuilder()
					.setTrapped(GadpValueUtils.makePath(trapped.getPath()))
					.setSpec(GadpValueUtils.makePath(spec.getPath()))
					.setEffective(GadpValueUtils.makePath(breakpoint.getPath()));
			if (frame != null) {
				evt.setFrame(GadpValueUtils.makePath(frame.getPath()));
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(container.getPath()))
							.setBreakHitEvent(evt))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void invalidateCacheRequested(TargetObject object) {
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(object.getPath()))
							.setCacheInvalidateEvent(
								Gadp.CacheInvalidateEvent.getDefaultInstance()))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void memoryReadError(TargetMemory<?> memory, AddressRange range,
				DebuggerMemoryAccessException e) {
			// TODO: Ignore those generated by this client
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(memory.getPath()))
							.setMemoryErrorEvent(Gadp.MemoryErrorEvent.newBuilder()
									.setRange(GadpValueUtils.makeRange(range))
									.setMessage(e.getMessage())))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void memoryUpdated(TargetMemory<?> memory, Address address, byte[] data) {
			// TODO: Ignore those generated by this client
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(memory.getPath()))
							.setMemoryUpdateEvent(Gadp.MemoryUpdateEvent.newBuilder()
									.setAddress(GadpValueUtils.makeAddress(address))
									.setContent(ByteString.copyFrom(data))))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void registersUpdated(TargetRegisterBank<?> bank, Map<String, byte[]> updates) {
			// TODO: Ignore those generated by this client
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(bank.getPath()))
							.setRegisterUpdateEvent(Gadp.RegisterUpdateEvent.newBuilder()
									.addAllValue(GadpValueUtils.makeRegisterValues(updates))))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void event(TargetEventScope<?> object,
				TypedTargetObjectRef<? extends TargetThread<?>> eventThread, TargetEventType type,
				String description, List<Object> parameters) {
			Gadp.TargetEvent.Builder evt = Gadp.TargetEvent.newBuilder();
			if (eventThread != null) {
				evt.setEventThread(GadpValueUtils.makePath(eventThread.getPath()));
			}
			evt.setType(GadpValueUtils.makeTargetEventType(type));
			evt.setDescription(description);
			evt.addAllParameters(GadpValueUtils.makeValues(parameters));
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(object.getPath()))
							.setTargetEvent(evt))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}
	}

	protected static <T> T errorSendNotify(Throwable e) {
		Msg.error(GadpClientHandler.class, "Could not send notification: " + e);
		return null;
	}

	protected final DebuggerObjectModel model;
	protected final AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> channel;
	protected final ListenerForEvents listenerForEvents = new ListenerForEvents();
	// Keeps strong references and tells level of subscription
	protected final NavigableSet<TargetObject> subscriptions = new TreeSet<>();

	public GadpClientHandler(AbstractGadpServer server, AsynchronousSocketChannel sock) {
		super(server, sock);
		model = server.model;
		channel = new AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage>(sock);
	}

	@Override
	protected CompletableFuture<Void> launchAsync() {
		return AsyncUtils.loop(TypeSpec.VOID, loop -> {
			if (sock.isOpen()) {
				channel.read(Gadp.RootMessage::parseFrom).handle(loop::consume);
			}
			else {
				loop.exit();
			}
		}, TypeSpec.cls(Gadp.RootMessage.class), (msg, loop) -> {
			loop.repeat();
			try {
				processMessage(msg).exceptionally(e -> {
					replyError(msg, e).exceptionally(ee -> {
						Msg.error(this, "Could not send error reply: " + ee);
						return null;
					});
					return null;
				}); // Do not handle with loop. Loop is already repeating
			}
			catch (Throwable e) {
				replyError(msg, e).exceptionally(ee -> {
					Msg.error(this, "Could not send error reply: " + ee);
					return null;
				});
			}
		});
	}

	protected Gadp.RootMessage buildError(Gadp.RootMessage req, ErrorCode code, String message) {
		return Gadp.RootMessage.newBuilder()
				.setSequence(req.getSequence())
				.setErrorReply(Gadp.ErrorReply.newBuilder().setCode(code).setMessage(message))
				.build();
	}

	protected CompletableFuture<?> replyError(Gadp.RootMessage req, Throwable e) {
		Throwable t = AsyncUtils.unwrapThrowable(e);
		if (LOG_ERROR_REPLY_STACKS) {
			Msg.debug(this, "Error caused by request " + req, e);
		}
		else {
			Msg.debug(this, "Error caused by request " + req + ": " + e);
		}
		if (t instanceof GadpErrorException) {
			GadpErrorException error = (GadpErrorException) t;
			return channel.write(buildError(req, error.getCode(), error.getMessage()));
		}
		if (t instanceof UnsupportedOperationException) {
			return channel.write(buildError(req, ErrorCode.NOT_SUPPORTED, t.getMessage()));
		}
		if (t instanceof DebuggerModelNoSuchPathException) {
			return channel.write(buildError(req, ErrorCode.NO_OBJECT, t.getMessage()));
		}
		if (t instanceof DebuggerModelTypeException) {
			return channel.write(buildError(req, ErrorCode.NO_INTERFACE, t.getMessage()));
		}
		if (t instanceof DebuggerIllegalArgumentException) {
			return channel.write(buildError(req, ErrorCode.BAD_ARGUMENT, t.getMessage()));
		}
		if (t instanceof DebuggerMemoryAccessException) {
			return channel.write(buildError(req, ErrorCode.MEMORY_ACCESS, t.getMessage()));
		}
		if (t instanceof DebuggerRegisterAccessException) {
			return channel.write(buildError(req, ErrorCode.REGISTER_ACCESS, t.getMessage()));
		}
		if (t instanceof DebuggerUserException) {
			return channel.write(buildError(req, ErrorCode.USER_ERROR, t.getMessage()));
		}
		if (t instanceof DebuggerModelAccessException) {
			return channel.write(buildError(req, ErrorCode.MODEL_ACCESS, t.getMessage()));
		}
		return channel.write(buildError(req, ErrorCode.UNKNOWN, "Unknown server-side error"));
	}

	protected GadpVersion getVersion() {
		return GadpVersion.VER1;
	}

	protected CompletableFuture<?> processMessage(Gadp.RootMessage msg) {
		switch (msg.getMsgCase()) {
			case CONNECT_REQUEST:
				return processConnect(msg.getSequence(), msg.getConnectRequest());
			case PING_REQUEST:
				return processPing(msg.getSequence(), msg.getPingRequest());
			case ATTACH_REQUEST:
				return processAttach(msg.getSequence(), msg.getAttachRequest());
			case BREAK_CREATE_REQUEST:
				return processBreakCreate(msg.getSequence(), msg.getBreakCreateRequest());
			case BREAK_TOGGLE_REQUEST:
				return processBreakToggle(msg.getSequence(), msg.getBreakToggleRequest());
			case CACHE_INVALIDATE_REQUEST:
				return processCacheInvalidate(msg.getSequence(), msg.getCacheInvalidateRequest());
			case DELETE_REQUEST:
				return processDelete(msg.getSequence(), msg.getDeleteRequest());
			case DETACH_REQUEST:
				return processDetach(msg.getSequence(), msg.getDetachRequest());
			case EXECUTE_REQUEST:
				return processExecute(msg.getSequence(), msg.getExecuteRequest());
			case FOCUS_REQUEST:
				return processFocus(msg.getSequence(), msg.getFocusRequest());
			case INTERRUPT_REQUEST:
				return processInterrupt(msg.getSequence(), msg.getInterruptRequest());
			case KILL_REQUEST:
				return processKill(msg.getSequence(), msg.getKillRequest());
			case LAUNCH_REQUEST:
				return processLaunch(msg.getSequence(), msg.getLaunchRequest());
			case MEMORY_READ_REQUEST:
				return processMemoryRead(msg.getSequence(), msg.getMemoryReadRequest());
			case MEMORY_WRITE_REQUEST:
				return processMemoryWrite(msg.getSequence(), msg.getMemoryWriteRequest());
			case REGISTER_READ_REQUEST:
				return processRegisterRead(msg.getSequence(), msg.getRegisterReadRequest());
			case REGISTER_WRITE_REQUEST:
				return processRegisterWrite(msg.getSequence(), msg.getRegisterWriteRequest());
			case RESUME_REQUEST:
				return processResume(msg.getSequence(), msg.getResumeRequest());
			case STEP_REQUEST:
				return processStep(msg.getSequence(), msg.getStepRequest());
			case SUBSCRIBE_REQUEST:
				return processSubscribe(msg.getSequence(), msg.getSubscribeRequest());
			case INVOKE_REQUEST:
				return processInvoke(msg.getSequence(), msg.getInvokeRequest());
			default:
				throw new GadpErrorException(ErrorCode.BAD_REQUEST,
					"Unrecognized request: " + msg.getMsgCase());
		}
	}

	protected CompletableFuture<?> processConnect(int seqno, Gadp.ConnectRequest req) {
		String ver = getVersion().getName();
		if (!req.getVersionList().contains(ver)) {
			throw new GadpErrorException(ErrorCode.NO_VERSION, "No listed version is supported");
		}
		return channel.write(Gadp.RootMessage.newBuilder()
				.setSequence(seqno)
				.setConnectReply(Gadp.ConnectReply.newBuilder().setVersion(ver))
				.build());
	}

	protected CompletableFuture<?> processPing(int seqno, Gadp.PingRequest req) {
		return channel.write(Gadp.RootMessage.newBuilder()
				.setSequence(seqno)
				.setPingReply(Gadp.PingReply.newBuilder().setContent(req.getContent()))
				.build());
	}

	protected <T extends TargetObjectRef> T isObjectValuedAttribute(TargetObject parent,
			Map.Entry<String, ?> ent, Class<T> cls) {
		Object val = ent.getValue();
		if (!cls.isAssignableFrom(val.getClass())) {
			return null;
		}
		T ref = cls.cast(val);
		if (!ref.getPath().equals(PathUtils.extend(parent.getPath(), ent.getKey()))) {
			return null;
		}
		return ref;
	}

	protected void changeSubscription(TargetObject obj, boolean subscribed) {
		synchronized (subscriptions) {
			if (subscribed) {
				if (subscriptions.add(obj)) {
					obj.addListener(listenerForEvents);
				}
			}
			else {
				subscriptions.remove(obj);
				obj.removeListener(listenerForEvents);
			}
		}
	}

	protected boolean isSubscribed(TargetObject obj) {
		synchronized (subscriptions) {
			return subscriptions.contains(obj);
		}
	}

	protected boolean unsubscribeSubtree(TargetObject seed) {
		synchronized (subscriptions) {
			if (!subscriptions.remove(seed)) {
				return false;
			}
			Set<TargetObject> tail = subscriptions.tailSet(seed);
			for (Iterator<TargetObject> it = tail.iterator(); it.hasNext();) {
				TargetObject o = it.next();
				if (!PathUtils.isAncestor(seed.getPath(), o.getPath())) {
					break;
				}
				o.removeListener(listenerForEvents);
				it.remove();
			}
			return true;
		}
	}

	protected <T extends TargetObjectRef> CompletableFuture<Integer> sendDelta(TargetObject parent,
			Delta<TargetObjectRef, T> deltaE, Delta<?, ?> deltaA) {
		assert isSubscribed(parent); // If listening, we should be subscribed
		return channel.write(Gadp.RootMessage.newBuilder()
				.setEventNotification(Gadp.EventNotification.newBuilder()
						.setPath(GadpValueUtils.makePath(parent.getPath()))
						.setModelObjectEvent(Gadp.ModelObjectEvent.newBuilder()
								.setDelta(GadpValueUtils.makeDelta(parent, deltaE, deltaA))))
				.build());
	}

	/**
	 * @implNote To avoid duplicates and spurious messages, we adopt the following strategy: 1) Get
	 *           any elements and/or attributes for the object as requested. 2) Send the response
	 *           and install the listener on the object. 3) Check if the object's elements and/or
	 *           attributes have changed and send a delta immediately.
	 */
	protected CompletableFuture<?> processSubscribe(int seqno, Gadp.SubscribeRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelValue(path).thenCompose(val -> {
			DebuggerObjectModel.requireNonNull(val, path);
			TargetObject obj = GadpValueUtils.getTargetObjectNonLink(path, val);
			if (obj == null) {
				return channel.write(Gadp.RootMessage.newBuilder()
						.setSequence(seqno)
						.setSubscribeReply(Gadp.SubscribeReply.newBuilder()
								.setValue(GadpValueUtils.makeValue(path, val)))
						.build());
			}

			changeSubscription(obj, req.getSubscribe());
			AsyncFence fence = new AsyncFence();
			if (req.getFetchElements()) {
				fence.include(obj.fetchElements(req.getRefreshElements()));
			}
			if (req.getFetchAttributes()) {
				fence.include(obj.fetchAttributes(req.getRefreshAttributes()));
			}
			return fence.ready().thenCompose(__ -> {
				return channel.write(Gadp.RootMessage.newBuilder()
						.setSequence(seqno)
						.setSubscribeReply(Gadp.SubscribeReply.newBuilder()
								.setValue(Gadp.Value.newBuilder()
										.setObjectInfo(GadpValueUtils.makeInfo(obj))))
						.build());
			});
		});
	}

	protected CompletableFuture<?> processInvoke(int seqno, Gadp.InvokeRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetMethod<?> method =
				DebuggerObjectModel.requireIface(TargetMethod.class, obj, path);
			return method.invoke(GadpValueUtils.getArguments(model, req.getArgumentList()));
		}).thenCompose(result -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setInvokeReply(Gadp.InvokeReply.newBuilder()
							.setResult(GadpValueUtils.makeValue(null, result)))
					.build());
		});
	}

	protected CompletableFuture<?> processAttach(int seqno, Gadp.AttachRequest req) {
		ProtocolStringList path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetAttacher<?> attacher =
				DebuggerObjectModel.requireIface(TargetAttacher.class, obj, path);
			switch (req.getSpecCase()) {
				case TARGET:
					TypedTargetObjectRef<GadpClientTargetAttachable> attachable =
						model.createRef(req.getTarget().getEList())
								.as(GadpClientTargetAttachable.class);
					return attacher.attach(attachable);
				case PID:
					return attacher.attach(req.getPid());
				default:
					throw new GadpErrorException(ErrorCode.BAD_REQUEST,
						"Unrecognized attach specification:" + req);
			}
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setAttachReply(Gadp.AttachReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processBreakCreate(int seqno, Gadp.BreakCreateRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetBreakpointContainer<?> breaks = DebuggerObjectModel
					.requireIface(TargetBreakpointContainer.class, obj, req.getPath().getEList());
			Set<TargetBreakpointKind> kinds = GadpValueUtils.getBreakKindSet(req.getKinds());
			switch (req.getSpecCase()) {
				case EXPRESSION:
					return breaks.placeBreakpoint(req.getExpression(), kinds);
				case ADDRESS:
					AddressRange range = server.getAddressRange(req.getAddress());
					return breaks.placeBreakpoint(range, kinds);
				default:
					throw new GadpErrorException(ErrorCode.BAD_REQUEST,
						"Unrecognized breakpoint specification: " + req);
			}
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setBreakCreateReply(Gadp.BreakCreateReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processBreakToggle(int seqno, Gadp.BreakToggleRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetBreakpointSpec<?> spec = DebuggerObjectModel
					.requireIface(TargetBreakpointSpec.tclass, obj, req.getPath().getEList());
			return spec.toggle(req.getEnabled());
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setBreakToggleReply(Gadp.BreakToggleReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processDelete(int seqno, Gadp.DeleteRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetDeletable<?> del = DebuggerObjectModel.requireIface(TargetDeletable.tclass, obj,
				req.getPath().getEList());
			return del.delete();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setDeleteReply(Gadp.DeleteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processDetach(int seqno, Gadp.DetachRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetDetachable<?> det = DebuggerObjectModel.requireIface(TargetDetachable.tclass, obj,
				req.getPath().getEList());
			return det.detach();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setDetachReply(Gadp.DetachReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processExecute(int seqno, Gadp.ExecuteRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetInterpreter<?> interpreter = DebuggerObjectModel
					.requireIface(TargetInterpreter.tclass, obj, req.getPath().getEList());
			if (req.getCapture()) {
				return interpreter.executeCapture(req.getCommand());
			}
			return interpreter.execute(req.getCommand()).thenApply(__ -> "");
		}).thenCompose(out -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setExecuteReply(Gadp.ExecuteReply.newBuilder().setCaptured(out))
					.build());
		});
	}

	protected CompletableFuture<?> processFocus(int seqno, Gadp.FocusRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetFocusScope<?> scope = DebuggerObjectModel.requireIface(TargetFocusScope.tclass,
				obj, req.getPath().getEList());
			return scope.requestFocus(model.createRef(req.getFocus().getEList()));
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setFocusReply(Gadp.FocusReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processInterrupt(int seqno, Gadp.InterruptRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetInterruptible<?> interruptible = DebuggerObjectModel
					.requireIface(TargetInterruptible.tclass, obj, req.getPath().getEList());
			return interruptible.interrupt();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setInterruptReply(Gadp.InterruptReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processCacheInvalidate(int seqno,
			Gadp.CacheInvalidateRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			return DebuggerObjectModel.requireNonNull(obj, req.getPath().getEList())
					.invalidateCaches();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setCacheInvalidateReply(Gadp.CacheInvalidateReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processKill(int seqno, Gadp.KillRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetKillable<?> killable = DebuggerObjectModel.requireIface(TargetKillable.class, obj,
				req.getPath().getEList());
			return killable.kill();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setKillReply(Gadp.KillReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processLaunch(int seqno, Gadp.LaunchRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetLauncher<?> launcher = DebuggerObjectModel.requireIface(TargetLauncher.class, obj,
				req.getPath().getEList());
			return launcher.launch(GadpValueUtils.getArguments(model, req.getArgumentList()));
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setLaunchReply(Gadp.LaunchReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processMemoryRead(int seqno, Gadp.MemoryReadRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetMemory<?> memory =
				DebuggerObjectModel.requireIface(TargetMemory.class, obj, req.getPath().getEList());
			AddressRange range = GadpValueUtils.getAddressRange(memory.getModel(), req.getRange());
			return memory.readMemory(range.getMinAddress(), (int) range.getLength());
		}).thenCompose(data -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setMemoryReadReply(
						Gadp.MemoryReadReply.newBuilder().setContent(ByteString.copyFrom(data)))
					.build());
		});
	}

	protected CompletableFuture<?> processMemoryWrite(int seqno, Gadp.MemoryWriteRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetMemory<?> memory =
				DebuggerObjectModel.requireIface(TargetMemory.class, obj, req.getPath().getEList());
			Address start = GadpValueUtils.getAddress(memory.getModel(), req.getStart());
			// TODO: Spare a copy by specifying a ByteBuffer variant of writeMemory?
			return memory.writeMemory(start, req.getContent().toByteArray());
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setMemoryWriteReply(Gadp.MemoryWriteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processRegisterRead(int seqno, Gadp.RegisterReadRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetRegisterBank<?> bank = DebuggerObjectModel.requireIface(TargetRegisterBank.class,
				obj, req.getPath().getEList());
			return bank.readRegistersNamed(req.getNameList());
		}).thenCompose(data -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setRegisterReadReply(Gadp.RegisterReadReply.newBuilder()
							.addAllValue(GadpValueUtils.makeRegisterValues(data)))
					.build());
		});
	}

	protected CompletableFuture<?> processRegisterWrite(int seqno, Gadp.RegisterWriteRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetRegisterBank<?> bank = DebuggerObjectModel.requireIface(TargetRegisterBank.class,
				obj, req.getPath().getEList());
			Map<String, byte[]> values = new LinkedHashMap<>();
			for (Gadp.RegisterValue rv : req.getValueList()) {
				values.put(rv.getName(), rv.getContent().toByteArray());
			}
			return bank.writeRegistersNamed(values);
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setRegisterWriteReply(Gadp.RegisterWriteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processResume(int seqno, Gadp.ResumeRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetResumable<?> resumable = DebuggerObjectModel.requireIface(TargetResumable.class,
				obj, req.getPath().getEList());
			return resumable.resume();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setResumeReply(Gadp.ResumeReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processStep(int seqno, Gadp.StepRequest req) {
		return model.fetchModelObject(req.getPath().getEList()).thenCompose(obj -> {
			TargetSteppable<?> steppable = DebuggerObjectModel.requireIface(TargetSteppable.class,
				obj, req.getPath().getEList());
			return steppable.step(GadpValueUtils.getStepKind(req.getKind()));
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setStepReply(Gadp.StepReply.getDefaultInstance())
					.build());
		});
	}
}
