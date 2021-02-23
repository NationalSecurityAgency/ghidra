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

import java.nio.channels.AsynchronousByteChannel;
import java.nio.channels.AsynchronousSocketChannel;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.google.protobuf.ByteString;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.comm.service.AbstractAsyncClientHandler;
import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.error.*;
import ghidra.dbg.gadp.GadpVersion;
import ghidra.dbg.gadp.client.GadpClientTargetAttachable;
import ghidra.dbg.gadp.client.GadpValueUtils;
import ghidra.dbg.gadp.error.GadpErrorException;
import ghidra.dbg.gadp.protocol.Gadp;
import ghidra.dbg.gadp.protocol.Gadp.ErrorCode;
import ghidra.dbg.gadp.util.AsyncProtobufMessageChannel;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointSpec.TargetBreakpointKind;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetConsole.TargetTextConsoleListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.XmlSchemaContext;
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

	protected class ListenerForEvents implements DebuggerModelListener, TargetTextConsoleListener {
		@Override
		public void created(TargetObject object) {
			if (!sock.isOpen()) {
				return;
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(object.getPath()))
							.setObjectCreatedEvent(Gadp.ObjectCreatedEvent.newBuilder()
									.setTypeHint(object.getTypeHint())
									.addAllInterface(object.getInterfaceNames())))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void rootAdded(TargetObject root) {
			if (!sock.isOpen()) {
				return;
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setRootAddedEvent(Gadp.RootAddedEvent.getDefaultInstance()))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void attributesChanged(TargetObject parent, Collection<String> removed,
				Map<String, ?> added) {
			if (!sock.isOpen()) {
				return;
			}
			// TODO: Can elements and attributes be combined into one message?
			if (removed.isEmpty() && added.isEmpty()) {
				return;
			}
			sendDelta(parent.getPath(), Delta.empty(), Delta.create(removed, added))
					.exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void elementsChanged(TargetObject parent, Collection<String> removed,
				Map<String, ? extends TargetObjectRef> added) {
			if (!sock.isOpen()) {
				return;
			}
			// TODO: Can elements and attributes be combined into one message?
			if (removed.isEmpty() && added.isEmpty()) {
				return;
			}
			sendDelta(parent.getPath(), Delta.create(removed, added), Delta.empty())
					.exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void invalidated(TargetObject object, TargetObject branch, String reason) {
			if (!sock.isOpen()) {
				return;
			}
			if (object != branch) {
				return;
			}
			channel.write(Gadp.RootMessage.newBuilder()
					.setEventNotification(Gadp.EventNotification.newBuilder()
							.setPath(GadpValueUtils.makePath(object.getPath()))
							.setObjectInvalidateEvent(
								Gadp.ObjectInvalidateEvent.newBuilder().setReason(reason)))
					.build()).exceptionally(GadpClientHandler::errorSendNotify);
		}

		@Override
		public void consoleOutput(TargetObject console, Channel c, byte[] data) {
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
			consoleOutput(console, c, out.getBytes(TargetConsole.CHARSET));
		}

		@Override
		public void breakpointHit(TargetBreakpointContainer<?> container, TargetObjectRef trapped,
				TypedTargetObjectRef<? extends TargetStackFrame<?>> frame,
				TypedTargetObjectRef<? extends TargetBreakpointSpec<?>> spec,
				TypedTargetObjectRef<? extends TargetBreakpointLocation<?>> breakpoint) {
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
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
			if (!sock.isOpen()) {
				return;
			}
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

	public GadpClientHandler(AbstractGadpServer server, AsynchronousSocketChannel sock) {
		super(server, sock);
		model = server.model;
		channel = createMessageChannel(sock);
	}

	protected AsyncProtobufMessageChannel<Gadp.RootMessage, Gadp.RootMessage> createMessageChannel(
			AsynchronousByteChannel byteChannel) {
		return new AsyncProtobufMessageChannel<>(byteChannel);
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
					e.printStackTrace();
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
			return channel.write(buildError(req, ErrorCode.EC_NOT_SUPPORTED, t.getMessage()));
		}
		if (t instanceof DebuggerModelNoSuchPathException) {
			return channel.write(buildError(req, ErrorCode.EC_NO_OBJECT, t.getMessage()));
		}
		if (t instanceof DebuggerModelTypeException) {
			return channel.write(buildError(req, ErrorCode.EC_NO_INTERFACE, t.getMessage()));
		}
		if (t instanceof DebuggerIllegalArgumentException) {
			return channel.write(buildError(req, ErrorCode.EC_BAD_ARGUMENT, t.getMessage()));
		}
		if (t instanceof DebuggerMemoryAccessException) {
			return channel.write(buildError(req, ErrorCode.EC_MEMORY_ACCESS, t.getMessage()));
		}
		if (t instanceof DebuggerRegisterAccessException) {
			return channel.write(buildError(req, ErrorCode.EC_REGISTER_ACCESS, t.getMessage()));
		}
		if (t instanceof DebuggerUserException) {
			return channel.write(buildError(req, ErrorCode.EC_USER_ERROR, t.getMessage()));
		}
		if (t instanceof DebuggerModelAccessException) {
			return channel.write(buildError(req, ErrorCode.EC_MODEL_ACCESS, t.getMessage()));
		}
		return channel.write(buildError(req, ErrorCode.EC_UNKNOWN, "Unknown server-side error"));
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
			case INVOKE_REQUEST:
				return processInvoke(msg.getSequence(), msg.getInvokeRequest());
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
			case RESYNC_REQUEST:
				return processResync(msg.getSequence(), msg.getResyncRequest());
			case RESUME_REQUEST:
				return processResume(msg.getSequence(), msg.getResumeRequest());
			case STEP_REQUEST:
				return processStep(msg.getSequence(), msg.getStepRequest());
			default:
				throw new GadpErrorException(Gadp.ErrorCode.EC_BAD_REQUEST,
					"Unrecognized request: " + msg.getMsgCase());
		}
	}

	protected CompletableFuture<?> processConnect(int seqno, Gadp.ConnectRequest req) {
		String ver = getVersion().getName();
		if (!req.getVersionList().contains(ver)) {
			throw new GadpErrorException(Gadp.ErrorCode.EC_NO_VERSION,
				"No listed version is supported");
		}
		TargetObjectSchema rootSchema = model.getRootSchema();
		CompletableFuture<Integer> send = channel.write(Gadp.RootMessage.newBuilder()
				.setSequence(seqno)
				.setConnectReply(Gadp.ConnectReply.newBuilder()
						.setVersion(ver)
						.setSchemaContext(XmlSchemaContext.serialize(rootSchema.getContext()))
						.setRootSchema(rootSchema.getName().toString()))
				.build());
		return send.thenAccept(__ -> {
			model.addModelListener(listenerForEvents, true);
		});
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

	protected <T extends TargetObjectRef> CompletableFuture<Integer> sendDelta(
			List<String> parentPath, Delta<TargetObjectRef, T> deltaE, Delta<?, ?> deltaA) {
		return channel.write(Gadp.RootMessage.newBuilder()
				.setEventNotification(Gadp.EventNotification.newBuilder()
						.setPath(GadpValueUtils.makePath(parentPath))
						.setModelObjectEvent(Gadp.ModelObjectEvent.newBuilder()
								.setElementDelta(
									GadpValueUtils.makeElementDelta(parentPath, deltaE))
								.setAttributeDelta(
									GadpValueUtils.makeElementDelta(parentPath, deltaA))))
				.build());
	}

	protected CompletableFuture<?> processInvoke(int seqno, Gadp.InvokeRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetMethod<?> method =
				DebuggerObjectModel.requireIface(TargetMethod.class, obj, path);
			return method.invoke(GadpValueUtils.getArguments(model, req.getArgumentList()));
		}).thenCompose(result -> {
			return model.flushEvents().thenApply(__ -> result);
		}).thenCompose(result -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setInvokeReply(Gadp.InvokeReply.newBuilder()
							.setResult(GadpValueUtils.makeValue(null, result)))
					.build());
		});
	}

	protected CompletableFuture<?> processResync(int seqno, Gadp.ResyncRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			return obj.resync(req.getAttributes(), req.getElements());
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setResyncReply(Gadp.ResyncReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processAttach(int seqno, Gadp.AttachRequest req) {
		List<String> path = req.getPath().getEList();
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
					throw new GadpErrorException(Gadp.ErrorCode.EC_BAD_REQUEST,
						"Unrecognized attach specification:" + req);
			}
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setAttachReply(Gadp.AttachReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processBreakCreate(int seqno, Gadp.BreakCreateRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetBreakpointContainer<?> breaks =
				DebuggerObjectModel.requireIface(TargetBreakpointContainer.class, obj, path);
			Set<TargetBreakpointKind> kinds = GadpValueUtils.getBreakKindSet(req.getKinds());
			switch (req.getSpecCase()) {
				case EXPRESSION:
					return breaks.placeBreakpoint(req.getExpression(), kinds);
				case ADDRESS:
					AddressRange range = server.getAddressRange(req.getAddress());
					return breaks.placeBreakpoint(range, kinds);
				default:
					throw new GadpErrorException(Gadp.ErrorCode.EC_BAD_REQUEST,
						"Unrecognized breakpoint specification: " + req);
			}
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setBreakCreateReply(Gadp.BreakCreateReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processBreakToggle(int seqno, Gadp.BreakToggleRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetBreakpointSpec<?> spec =
				DebuggerObjectModel.requireIface(TargetBreakpointSpec.tclass, obj, path);
			return spec.toggle(req.getEnabled());
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setBreakToggleReply(Gadp.BreakToggleReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processDelete(int seqno, Gadp.DeleteRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetDeletable<?> del =
				DebuggerObjectModel.requireIface(TargetDeletable.tclass, obj, path);
			return del.delete();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setDeleteReply(Gadp.DeleteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processDetach(int seqno, Gadp.DetachRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetDetachable<?> det =
				DebuggerObjectModel.requireIface(TargetDetachable.tclass, obj, path);
			return det.detach();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setDetachReply(Gadp.DetachReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processExecute(int seqno, Gadp.ExecuteRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetInterpreter<?> interpreter =
				DebuggerObjectModel.requireIface(TargetInterpreter.tclass, obj, path);
			if (req.getCapture()) {
				return interpreter.executeCapture(req.getCommand());
			}
			return interpreter.execute(req.getCommand()).thenApply(__ -> "");
		}).thenCompose(out -> {
			return model.flushEvents().thenApply(__ -> out);
		}).thenCompose(out -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setExecuteReply(Gadp.ExecuteReply.newBuilder().setCaptured(out))
					.build());
		});
	}

	protected CompletableFuture<?> processFocus(int seqno, Gadp.FocusRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetFocusScope<?> scope =
				DebuggerObjectModel.requireIface(TargetFocusScope.tclass, obj, path);
			return scope.requestFocus(model.createRef(req.getFocus().getEList()));
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setFocusReply(Gadp.FocusReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processInterrupt(int seqno, Gadp.InterruptRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetInterruptible<?> interruptible =
				DebuggerObjectModel.requireIface(TargetInterruptible.tclass, obj, path);
			return interruptible.interrupt();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setInterruptReply(Gadp.InterruptReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processCacheInvalidate(int seqno,
			Gadp.CacheInvalidateRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			return DebuggerObjectModel.requireNonNull(obj, path).invalidateCaches();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setCacheInvalidateReply(Gadp.CacheInvalidateReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processKill(int seqno, Gadp.KillRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetKillable<?> killable =
				DebuggerObjectModel.requireIface(TargetKillable.class, obj, path);
			return killable.kill();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setKillReply(Gadp.KillReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processLaunch(int seqno, Gadp.LaunchRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			Msg.debug(this, "Launching: " + Thread.currentThread());
			TargetLauncher<?> launcher =
				DebuggerObjectModel.requireIface(TargetLauncher.class, obj, path);
			return launcher.launch(GadpValueUtils.getArguments(model, req.getArgumentList()));
		}).thenCompose(__ -> {
			Msg.debug(this, "Flushing events after launch: " + Thread.currentThread());
			return model.flushEvents();
		}).thenCompose(__ -> {
			Msg.debug(this, "Responding after launch: " + Thread.currentThread());
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setLaunchReply(Gadp.LaunchReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processMemoryRead(int seqno, Gadp.MemoryReadRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetMemory<?> memory =
				DebuggerObjectModel.requireIface(TargetMemory.class, obj, path);
			AddressRange range = GadpValueUtils.getAddressRange(memory.getModel(), req.getRange());
			return memory.readMemory(range.getMinAddress(), (int) range.getLength());
		}).thenCompose(data -> {
			return model.flushEvents().thenApply(__ -> data);
		}).thenCompose(data -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setMemoryReadReply(
						Gadp.MemoryReadReply.newBuilder().setContent(ByteString.copyFrom(data)))
					.build());
		});
	}

	protected CompletableFuture<?> processMemoryWrite(int seqno, Gadp.MemoryWriteRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetMemory<?> memory =
				DebuggerObjectModel.requireIface(TargetMemory.class, obj, path);
			Address start = GadpValueUtils.getAddress(memory.getModel(), req.getStart());
			// TODO: Spare a copy by specifying a ByteBuffer variant of writeMemory?
			return memory.writeMemory(start, req.getContent().toByteArray());
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setMemoryWriteReply(Gadp.MemoryWriteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processRegisterRead(int seqno, Gadp.RegisterReadRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetRegisterBank<?> bank =
				DebuggerObjectModel.requireIface(TargetRegisterBank.class, obj, path);
			return bank.readRegistersNamed(req.getNameList());
		}).thenCompose(data -> {
			return model.flushEvents().thenApply(__ -> data);
		}).thenCompose(data -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setRegisterReadReply(Gadp.RegisterReadReply.newBuilder()
							.addAllValue(GadpValueUtils.makeRegisterValues(data)))
					.build());
		});
	}

	protected CompletableFuture<?> processRegisterWrite(int seqno, Gadp.RegisterWriteRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetRegisterBank<?> bank =
				DebuggerObjectModel.requireIface(TargetRegisterBank.class, obj, path);
			Map<String, byte[]> values = new LinkedHashMap<>();
			for (Gadp.RegisterValue rv : req.getValueList()) {
				values.put(rv.getName(), rv.getContent().toByteArray());
			}
			return bank.writeRegistersNamed(values);
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setRegisterWriteReply(Gadp.RegisterWriteReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processResume(int seqno, Gadp.ResumeRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetResumable<?> resumable =
				DebuggerObjectModel.requireIface(TargetResumable.class, obj, path);
			return resumable.resume();
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setResumeReply(Gadp.ResumeReply.getDefaultInstance())
					.build());
		});
	}

	protected CompletableFuture<?> processStep(int seqno, Gadp.StepRequest req) {
		List<String> path = req.getPath().getEList();
		return model.fetchModelObject(path).thenCompose(obj -> {
			TargetSteppable<?> steppable =
				DebuggerObjectModel.requireIface(TargetSteppable.class, obj, path);
			return steppable.step(GadpValueUtils.getStepKind(req.getKind()));
		}).thenCompose(__ -> {
			return model.flushEvents();
		}).thenCompose(__ -> {
			return channel.write(Gadp.RootMessage.newBuilder()
					.setSequence(seqno)
					.setStepReply(Gadp.StepReply.getDefaultInstance())
					.build());
		});
	}
}
