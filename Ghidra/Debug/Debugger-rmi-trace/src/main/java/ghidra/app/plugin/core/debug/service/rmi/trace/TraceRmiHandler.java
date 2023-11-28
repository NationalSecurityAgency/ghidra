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
package ghidra.app.plugin.core.debug.service.rmi.trace;

import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;

import com.google.protobuf.ByteString;

import db.Transaction;
import ghidra.app.plugin.core.debug.disassemble.DebuggerDisassemblerPlugin;
import ghidra.app.plugin.core.debug.disassemble.TraceDisassembleCommand;
import ghidra.app.services.DebuggerControlService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.target.schema.XmlSchemaContext;
import ghidra.dbg.util.PathPattern;
import ghidra.dbg.util.PathUtils;
import ghidra.debug.api.target.ActionName;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.AutoService.Wiring;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.util.DefaultLanguageService;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.rmi.trace.TraceRmi.Compiler;
import ghidra.rmi.trace.TraceRmi.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateFileException;
import ghidra.util.task.TaskMonitor;

public class TraceRmiHandler implements TraceRmiConnection {
	public static final String VERSION = "10.4";

	protected static class VersionMismatchError extends TraceRmiError {
		public VersionMismatchError(String remote) {
			super("Mismatched versions: Front-end: %s, back-end: %s.".formatted(VERSION, remote));
		}
	}

	protected static class InvalidRequestError extends TraceRmiError {
		public InvalidRequestError(RootMessage req) {
			super("Unrecognized or out-of-sequence request: " + req);
		}
	}

	protected static class InvalidDomObjIdError extends TraceRmiError {
	}

	protected static class DomObjIdInUseError extends TraceRmiError {
	}

	protected static class InvalidObjIdError extends TraceRmiError {
	}

	protected static class InvalidObjPathError extends TraceRmiError {
	}

	protected static class NoSuchAddressSpaceError extends TraceRmiError {
	}

	protected static class InvalidSchemaError extends TraceRmiError {
		public InvalidSchemaError(Throwable cause) {
			super(cause);
		}
	}

	protected static class InvalidRegisterError extends TraceRmiError {
		public InvalidRegisterError(String name) {
			super("Invalid register: " + name);
		}
	}

	protected static class InvalidTxIdError extends TraceRmiError {
		public InvalidTxIdError(int id) {
			super("txid=" + id);
		}
	}

	protected static class TxIdInUseError extends TraceRmiError {
	}

	protected record DoId(int domObjId) {
		public DoId(DomObjId oid) {
			this(oid.getId());
		}

		public DomObjId toDomObjId() {
			return DomObjId.newBuilder().setId(domObjId).build();
		}
	}

	protected record Tid(DoId doId, int txId) {
	}

	protected record OpenTx(Tid txId, Transaction tx, boolean undoable) {
	}

	protected class OpenTraceMap {
		private final Map<DoId, OpenTrace> byId = new HashMap<>();
		private final Map<Trace, OpenTrace> byTrace = new HashMap<>();
		private final CompletableFuture<OpenTrace> first = new CompletableFuture<>();

		public synchronized boolean isEmpty() {
			return byId.isEmpty();
		}

		public synchronized Set<DoId> idSet() {
			return Set.copyOf(byId.keySet());
		}

		public synchronized OpenTrace removeById(DoId id) {
			OpenTrace removed = byId.remove(id);
			if (removed == null) {
				return null;
			}
			byTrace.remove(removed.trace);
			plugin.withdrawTarget(removed.target);
			return removed;
		}

		public synchronized OpenTrace removeByTrace(Trace trace) {
			OpenTrace removed = byTrace.remove(trace);
			if (removed == null) {
				return null;
			}
			byId.remove(removed.doId);
			plugin.withdrawTarget(removed.target);
			return removed;
		}

		public synchronized OpenTrace getById(DoId doId) {
			return byId.get(doId);
		}

		public synchronized OpenTrace getByTrace(Trace trace) {
			return byTrace.get(trace);
		}

		public synchronized void put(OpenTrace openTrace) {
			byId.put(openTrace.doId, openTrace);
			byTrace.put(openTrace.trace, openTrace);
			first.complete(openTrace);

			plugin.publishTarget(openTrace.target);
		}

		public CompletableFuture<OpenTrace> getFirstAsync() {
			return first;
		}
	}

	private final TraceRmiPlugin plugin;
	private final Socket socket;
	private final InputStream in;
	private final OutputStream out;
	private final CompletableFuture<Void> negotiate = new CompletableFuture<>();
	private final CompletableFuture<Void> closed = new CompletableFuture<>();
	private final Set<TerminalSession> terminals = new LinkedHashSet<>();

	private final OpenTraceMap openTraces = new OpenTraceMap();
	private final Map<Tid, OpenTx> openTxes = new HashMap<>();

	private final DefaultRemoteMethodRegistry methodRegistry = new DefaultRemoteMethodRegistry();
	// The remote must service requests and reply in the order received.
	private final Deque<DefaultRemoteAsyncResult> xReqQueue = new ArrayDeque<>();

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@AutoServiceConsumed
	private DebuggerControlService controlService;
	@SuppressWarnings("unused")
	private final Wiring autoServiceWiring;

	/**
	 * Create a handler
	 * 
	 * <p>
	 * Note it is common for this to be constructed by a TCP <em>client</em>.
	 * 
	 * @param socket the socket to the back-end debugger
	 * @throws IOException if there is an issue with the I/O streams
	 */
	public TraceRmiHandler(TraceRmiPlugin plugin, Socket socket) throws IOException {
		this.plugin = plugin;
		plugin.addHandler(this);
		this.socket = socket;
		this.in = socket.getInputStream();
		this.out = socket.getOutputStream();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		this.negotiate();
	}

	protected void flushXReqQueue(Throwable exc) {
		List<DefaultRemoteAsyncResult> copy;
		synchronized (xReqQueue) {
			copy = List.copyOf(xReqQueue);
			xReqQueue.clear();
		}
		for (DefaultRemoteAsyncResult result : copy) {
			result.completeExceptionally(exc);
		}
	}

	protected void terminateTerminals() {
		List<TerminalSession> terminals;
		synchronized (this.terminals) {
			terminals = List.copyOf(this.terminals);
			this.terminals.clear();
		}
		for (TerminalSession term : terminals) {
			CompletableFuture.runAsync(() -> {
				try {
					term.terminate();
				}
				catch (Exception e) {
					Msg.error(this, "Could not terminate " + term + ": " + e);
				}
			});
		}
	}

	public void dispose() throws IOException {
		plugin.removeHandler(this);
		flushXReqQueue(new TraceRmiError("Socket closed"));

		terminateTerminals();

		socket.close();
		while (!openTxes.isEmpty()) {
			Tid nextKey = openTxes.keySet().iterator().next();
			OpenTx open = openTxes.remove(nextKey);
			open.tx.close();
		}
		while (!openTraces.isEmpty()) {
			DoId nextKey = openTraces.idSet().iterator().next();
			OpenTrace open = openTraces.removeById(nextKey);
			if (traceManager == null || traceManager.isSaveTracesByDefault()) {
				try {
					open.trace.save("Save on Disconnect", plugin.getTaskMonitor());
				}
				catch (IOException e) {
					Msg.error(this, "Could not save " + open.trace);
				}
				catch (CancelledException e) {
					// OK. Move on
				}
			}
			open.trace.release(this);
		}
		closed.complete(null);
	}

	@Override
	public void close() throws IOException {
		dispose();
	}

	@Override
	public boolean isClosed() {
		return socket.isClosed() && closed.isDone();
	}

	@Override
	public void waitClosed() {
		try {
			closed.get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new TraceRmiError(e);
		}
	}

	protected DomainFolder getOrCreateNewTracesFolder()
			throws InvalidNameException, IOException {
		return getOrCreateFolder(plugin.getTool().getProject().getProjectData().getRootFolder(),
			"New Traces");
	}

	protected DomainFolder getOrCreateFolder(DomainFolder parent, String name)
			throws InvalidNameException, IOException {
		try {
			return parent.createFolder(name);
		}
		catch (DuplicateFileException e) {
			return parent.getFolder(name);
		}
	}

	protected DomainFolder createFolders(DomainFolder parent, List<String> path)
			throws InvalidNameException, IOException {
		return createFolders(parent, path, 0);
	}

	protected DomainFolder createFolders(DomainFolder parent, List<String> path, int index)
			throws InvalidNameException, IOException {
		if (path == null && index == 0 || index == path.size()) {
			return parent;
		}
		String name = path.get(index);
		return createFolders(getOrCreateFolder(parent, name), path, index + 1);
	}

	protected DomainFile createDeconflictedFile(DomainFolder parent, DomainObject object)
			throws InvalidNameException, CancelledException, IOException {
		String name = object.getName();
		TaskMonitor monitor = plugin.getTaskMonitor();
		for (int nextId = 1; nextId < 100; nextId++) {
			try {
				return parent.createFile(name, object, monitor);
			}
			catch (DuplicateFileException e) {
				name = object.getName() + "." + nextId;
			}
		}
		name = object.getName() + "." + System.currentTimeMillis();
		// Don't catch it this last time
		return parent.createFile(name, object, monitor);
	}

	public void start() {
		new Thread(this::receiveLoop, "trace-rmi handler " + socket.getRemoteSocketAddress())
				.start();
	}

	protected RootMessage receive() {
		try {
			// May return null when the socket is closed normally
			return recvDelimited(in);
		}
		catch (IOException e) {
			// Also return null for abnormal closure
			Msg.error(this, "Cannot read packet: " + e);
			flushXReqQueue(e);
			return null;
		}
	}

	protected static void sendDelimited(OutputStream out, RootMessage msg, long dbgSeq)
			throws IOException {
		ByteBuffer buf = ByteBuffer.allocate(4);
		buf.putInt(msg.getSerializedSize());
		out.write(buf.array());
		msg.writeTo(out);
		out.flush();
	}

	protected static byte[] recvAll(InputStream in, int len) throws IOException {
		byte[] buf = new byte[len];
		int total = 0;
		while (total < len) {
			int l = in.read(buf, total, len - total);
			if (l <= 0) {
				return null;
			}
			total += l;
		}
		return buf;
	}

	protected static RootMessage recvDelimited(InputStream in) throws IOException {
		byte[] lenBuf = recvAll(in, Integer.BYTES);
		if (lenBuf == null) {
			return null;
		}
		int len = ByteBuffer.wrap(lenBuf).getInt();
		byte[] datBuf = recvAll(in, len);
		if (datBuf == null) {
			return null;
		}
		RootMessage msg = RootMessage.parseFrom(datBuf);
		return msg;
	}

	long dbgSeq = 0;

	protected boolean send(RootMessage rep) {
		try {
			synchronized (out) {
				sendDelimited(out, rep, dbgSeq++);
			}
			return true;
		}
		catch (IOException e) {
			Msg.error(this, "Cannot send reply", e);
			return false;
		}
	}

	public void receiveLoop() {
		try {
			while (true) {
				RootMessage req = receive();
				if (req == null) {
					// Either normal or abnormal closure
					return;
				}

				RootMessage rep = dispatchNominal.handle(req);
				if (rep == null) {
					// Handler did not generate a response
					continue;
				}

				if (!send(rep)) {
					return;
				}
			}
		}
		finally {
			try {
				dispose();
			}
			catch (IOException e) {
				Msg.error(this, "Could not close socket after error", e);
			}
		}
	}

	protected void negotiate() {
		RootMessage req = receive();
		RootMessage rep = dispatchNegotiate.handle(req);
		if (req == null) {
			throw new TraceRmiError("Could not receive negotiation request");
		}
		if (!send(rep)) {
			throw new TraceRmiError("Could not respond during negotiation");
		}
	}

	private interface Dispatcher {
		RootMessage.Builder dispatch(RootMessage req, RootMessage.Builder rep) throws Exception;

		default RootMessage handle(RootMessage req) {
			String desc = toString(req);
			if (desc != null) {
				TimedMsg.debug(this, "HANDLING: " + desc);
			}
			RootMessage.Builder rep = RootMessage.newBuilder();
			try {
				rep = dispatch(req, rep);
				return rep == null ? null : rep.build();
			}
			catch (Throwable e) {
				return rep
						.setError(ReplyError.newBuilder()
								.setMessage(
									e.getMessage() + "\n" + ExceptionUtils.getStackTrace(e)))
						.build();
			}
		}

		default String toString(RootMessage req) {
			return switch (req.getMsgCase()) {
				case REQUEST_ACTIVATE -> "activate(%d, %d, %s)".formatted(
					req.getRequestActivate().getOid().getId(),
					req.getRequestActivate().getObject().getId(),
					req.getRequestActivate().getObject().getPath().getPath());
				case REQUEST_END_TX -> "endTx(%d)".formatted(
					req.getRequestEndTx().getTxid().getId());
				case REQUEST_START_TX -> "startTx(%d,%s)".formatted(
					req.getRequestStartTx().getTxid().getId(),
					req.getRequestStartTx().getDescription());
				case REQUEST_SET_VALUE -> "setValue(%d,%s,%s)".formatted(
					req.getRequestSetValue().getValue().getParent().getId(),
					req.getRequestSetValue().getValue().getParent().getPath().getPath(),
					req.getRequestSetValue().getValue().getKey());
				default -> null;
			};
		}
	}

	final Dispatcher dispatchNegotiate = (req, rep) -> switch (req.getMsgCase()) {
		case REQUEST_NEGOTIATE -> rep
				.setReplyNegotiate(handleNegotiate(req.getRequestNegotiate()));
		default -> throw new InvalidRequestError(req);
	};

	final Dispatcher dispatchNominal = (req, rep) -> switch (req.getMsgCase()) {
		case REQUEST_ACTIVATE -> rep
				.setReplyActivate(handleActivate(req.getRequestActivate()));
		case REQUEST_CLOSE_TRACE -> rep
				.setReplyCloseTrace(handleCloseTrace(req.getRequestCloseTrace()));
		case REQUEST_CREATE_OBJECT -> rep
				.setReplyCreateObject(handleCreateObject(req.getRequestCreateObject()));
		case REQUEST_CREATE_OVERLAY -> rep
				.setReplyCreateOverlay(
					handleCreateOverlay(req.getRequestCreateOverlay()));
		case REQUEST_CREATE_ROOT_OBJECT -> rep
				.setReplyCreateObject(
					handleCreateRootObject(req.getRequestCreateRootObject()));
		case REQUEST_CREATE_TRACE -> rep
				.setReplyCreateTrace(handleCreateTrace(req.getRequestCreateTrace()));
		case REQUEST_DELETE_BYTES -> rep
				.setReplyDeleteBytes(handleDeleteBytes(req.getRequestDeleteBytes()));
		case REQUEST_DELETE_REGISTER_VALUE -> rep
				.setReplyDeleteRegisterValue(
					handleDeleteRegisterValue(req.getRequestDeleteRegisterValue()));
		case REQUEST_DISASSEMBLE -> rep
				.setReplyDisassemble(handleDisassemble(req.getRequestDisassemble()));
		case REQUEST_END_TX -> rep
				.setReplyEndTx(handleEndTx(req.getRequestEndTx()));
		case REQUEST_GET_OBJECT -> rep
				.setReplyGetObject(handleGetObject(req.getRequestGetObject()));
		case REQUEST_GET_VALUES -> rep
				.setReplyGetValues(handleGetValues(req.getRequestGetValues()));
		case REQUEST_GET_VALUES_INTERSECTING -> rep
				.setReplyGetValues(
					handleGetValuesIntersecting(req.getRequestGetValuesIntersecting()));
		case REQUEST_INSERT_OBJECT -> rep
				.setReplyInsertObject(handleInsertObject(req.getRequestInsertObject()));
		case REQUEST_PUT_BYTES -> rep
				.setReplyPutBytes(handlePutBytes(req.getRequestPutBytes()));
		case REQUEST_PUT_REGISTER_VALUE -> rep
				.setReplyPutRegisterValue(
					handlePutRegisterValue(req.getRequestPutRegisterValue()));
		case REQUEST_REMOVE_OBJECT -> rep
				.setReplyRemoveObject(handleRemoveObject(req.getRequestRemoveObject()));
		case REQUEST_RETAIN_VALUES -> rep
				.setReplyRetainValues(handleRetainValues(req.getRequestRetainValues()));
		case REQUEST_SAVE_TRACE -> rep
				.setReplySaveTrace(handleSaveTrace(req.getRequestSaveTrace()));
		case REQUEST_SET_MEMORY_STATE -> rep
				.setReplySetMemoryState(
					handleSetMemoryState(req.getRequestSetMemoryState()));
		case REQUEST_SET_VALUE -> rep
				.setReplySetValue(handleSetValue(req.getRequestSetValue()));
		case REQUEST_SNAPSHOT -> rep
				.setReplySnapshot(handleSnapshot(req.getRequestSnapshot()));
		case REQUEST_START_TX -> rep
				.setReplyStartTx(handleStartTx(req.getRequestStartTx()));
		case XREPLY_INVOKE_METHOD -> handleXInvokeMethod(req.getXreplyInvokeMethod());
		default -> throw new InvalidRequestError(req);
	};

	protected OpenTrace requireOpenTrace(DomObjId domObjId) {
		return requireOpenTrace(new DoId(domObjId));
	}

	protected OpenTrace requireOpenTrace(DoId doId) {
		OpenTrace open = openTraces.getById(doId);
		if (open == null) {
			throw new InvalidDomObjIdError();
		}
		return open;
	}

	protected DoId requireAvailableDoId(DomObjId domObjId) {
		return requireAvailableDoId(new DoId(domObjId));
	}

	protected DoId requireAvailableDoId(DoId doId) {
		OpenTrace open = openTraces.getById(doId);
		if (open != null) {
			throw new DomObjIdInUseError();
		}
		return doId;
	}

	protected Tid requireAvailableTid(OpenTrace open, TxId txid) {
		return requireAvailableTid(new Tid(open.doId, txid.getId()));
	}

	protected Tid requireAvailableTid(Tid tid) {
		OpenTx tx = openTxes.get(tid);
		if (tx != null) {
			throw new TxIdInUseError();
		}
		return tid;
	}

	protected CompilerSpec requireCompilerSpec(Language language, Compiler compiler)
			throws LanguageNotFoundException, CompilerSpecNotFoundException {
		return DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID(language.getId()))
				.getCompilerSpecByID(new CompilerSpecID(compiler.getId()));
	}

	protected static TraceObjectKeyPath toKeyPath(ObjPath path) {
		return TraceObjectKeyPath.parse(path.getPath());
	}

	protected static PathPattern toPathPattern(ObjPath path) {
		return new PathPattern(PathUtils.parse(path.getPath()));
	}

	protected static Lifespan toLifespan(Span span) {
		return Lifespan.span(span.getMin(), span.getMax());
	}

	protected static TraceMemoryState toMemoryState(MemoryState state) {
		return switch (state) {
			case MS_UNKNOWN -> TraceMemoryState.UNKNOWN;
			case MS_KNOWN -> TraceMemoryState.KNOWN;
			case MS_ERROR -> TraceMemoryState.ERROR;
			default -> throw new AssertionError();
		};
	}

	protected static ConflictResolution toResolution(Resolution resolution) {
		return switch (resolution) {
			case CR_DENY -> ConflictResolution.DENY;
			case CR_TRUNCATE -> ConflictResolution.TRUNCATE;
			case CR_ADJUST -> ConflictResolution.ADJUST;
			default -> throw new AssertionError();
		};
	}

	protected static ObjSpec makeObjSpec(TraceObject object) {
		return ObjSpec.newBuilder()
				.setId(object.getKey())
				.build();
	}

	protected static ObjPath makeObjPath(TraceObjectKeyPath path) {
		return ObjPath.newBuilder()
				.setPath(path.toString())
				.build();
	}

	protected static ObjDesc makeObjDesc(TraceObject object) {
		return ObjDesc.newBuilder()
				.setId(object.getKey())
				.setPath(makeObjPath(object.getCanonicalPath()))
				.build();
	}

	protected static ValDesc makeValDesc(TraceObjectValue value) {
		return ValDesc.newBuilder()
				.setParent(makeObjDesc(value.getParent()))
				.setSpan(makeSpan(value.getLifespan()))
				.setKey(value.getEntryKey())
				.setValue(makeValue(value.getValue()))
				.build();
	}

	protected static ValDesc makeValDesc(TraceObjectValPath valPath) {
		// TODO: If links are involved, explain them?
		return makeValDesc(valPath.getLastEntry());
	}

	protected static Span makeSpan(Lifespan lifespan) {
		if (lifespan.isEmpty()) {
			return Span.newBuilder().setMin(0).setMax(-1).build();
		}
		return Span.newBuilder().setMin(lifespan.lmin()).setMax(lifespan.lmax()).build();
	}

	protected static Addr makeAddr(Address address) {
		return Addr.newBuilder()
				.setSpace(address.getAddressSpace().getName())
				.setOffset(address.getOffset())
				.build();
	}

	protected static AddrRange makeAddrRange(AddressRange range) {
		return AddrRange.newBuilder()
				.setSpace(range.getAddressSpace().getName())
				.setOffset(range.getMinAddress().getOffset())
				.setExtend(range.getLength() - 1)
				.build();
	}

	protected static Value makeValue(Object value) {
		if (value instanceof Void) {
			return Value.newBuilder().setNullValue(Null.getDefaultInstance()).build();
		}
		if (value instanceof Boolean b) {
			return Value.newBuilder().setBoolValue(b).build();
		}
		if (value instanceof Byte b) {
			return Value.newBuilder().setByteValue(b).build();
		}
		if (value instanceof Character c) {
			return Value.newBuilder().setCharValue(c).build();
		}
		if (value instanceof Short s) {
			return Value.newBuilder().setShortValue(s).build();
		}
		if (value instanceof Integer i) {
			return Value.newBuilder().setIntValue(i).build();
		}
		if (value instanceof Long l) {
			return Value.newBuilder().setLongValue(l).build();
		}
		if (value instanceof String s) {
			return Value.newBuilder().setStringValue(s).build();
		}
		if (value instanceof boolean[] ba) {
			return Value.newBuilder()
					.setBoolArrValue(
						BoolArr.newBuilder().addAllArr(Arrays.asList(ArrayUtils.toObject(ba))))
					.build();
		}
		if (value instanceof byte[] ba) {
			return Value.newBuilder().setBytesValue(ByteString.copyFrom(ba)).build();
		}
		if (value instanceof char[] ca) {
			return Value.newBuilder().setCharArrValue(new String(ca)).build();
		}
		if (value instanceof short[] sa) {
			return Value.newBuilder()
					.setShortArrValue(ShortArr.newBuilder()
							.addAllArr(
								Stream.of(ArrayUtils.toObject(sa)).map(s -> (int) s).toList()))
					.build();
		}
		if (value instanceof int[] ia) {
			return Value.newBuilder()
					.setIntArrValue(
						IntArr.newBuilder()
								.addAllArr(IntStream.of(ia).mapToObj(i -> i).toList()))
					.build();
		}
		if (value instanceof long[] la) {
			return Value.newBuilder()
					.setLongArrValue(
						LongArr.newBuilder()
								.addAllArr(LongStream.of(la).mapToObj(l -> l).toList()))
					.build();
		}
		if (value instanceof String[] sa) {
			return Value.newBuilder()
					.setStringArrValue(StringArr.newBuilder().addAllArr(List.of(sa)))
					.build();
		}
		if (value instanceof Address a) {
			return Value.newBuilder().setAddressValue(makeAddr(a)).build();
		}
		if (value instanceof AddressRange r) {
			return Value.newBuilder().setRangeValue(makeAddrRange(r)).build();
		}
		if (value instanceof TraceObject o) {
			return Value.newBuilder().setChildDesc(makeObjDesc(o)).build();
		}
		throw new AssertionError(
			"Cannot encode value: " + value + "(type=" + value.getClass() + ")");
	}

	protected static MethodArgument makeArgument(String name, Object value) {
		return MethodArgument.newBuilder().setName(name).setValue(makeValue(value)).build();
	}

	protected static MethodArgument makeArgument(Map.Entry<String, Object> ent) {
		return makeArgument(ent.getKey(), ent.getValue());
	}

	protected boolean followsPresent(Trace trace) {
		DebuggerControlService controlService = this.controlService;
		if (controlService == null) {
			return true;
		}
		return controlService.getCurrentMode(trace).followsPresent();
	}

	protected ReplyActivate handleActivate(RequestActivate req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		TraceObject object = open.getObject(req.getObject(), true);
		DebuggerCoordinates coords = traceManager.getCurrent();
		if (coords.getTrace() != open.trace) {
			coords = DebuggerCoordinates.NOWHERE;
		}
		if (open.lastSnapshot != null && followsPresent(open.trace)) {
			coords = coords.snap(open.lastSnapshot.getKey());
		}
		DebuggerCoordinates finalCoords = coords.object(object);
		Swing.runLater(() -> {
			if (!traceManager.getOpenTraces().contains(open.trace)) {
				traceManager.openTrace(open.trace);
				traceManager.activate(finalCoords, ActivationCause.SYNC_MODEL);
			}
			else {
				Trace currentTrace = traceManager.getCurrentTrace();
				if (currentTrace == null || openTraces.getByTrace(currentTrace) != null) {
					traceManager.activate(finalCoords, ActivationCause.SYNC_MODEL);
				}
			}
		});
		return ReplyActivate.getDefaultInstance();
	}

	protected ReplyCloseTrace handleCloseTrace(RequestCloseTrace req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		openTraces.removeById(open.doId);
		open.trace.release(this);
		return ReplyCloseTrace.getDefaultInstance();
	}

	protected ReplyCreateObject handleCreateObject(RequestCreateObject req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		TraceObject object =
			open.trace.getObjectManager().createObject(toKeyPath(req.getPath()));
		return ReplyCreateObject.newBuilder().setObject(makeObjSpec(object)).build();
	}

	protected ReplyCreateOverlaySpace handleCreateOverlay(RequestCreateOverlaySpace req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		AddressSpace base = open.getSpace(req.getBaseSpace(), true);
		open.trace.getMemoryManager().getOrCreateOverlayAddressSpace(req.getName(), base);
		return ReplyCreateOverlaySpace.getDefaultInstance();
	}

	protected ReplyCreateObject handleCreateRootObject(RequestCreateRootObject req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		XmlSchemaContext ctx;
		try {
			ctx = XmlSchemaContext.deserialize(req.getSchemaContext());
		}
		catch (Exception e) {
			throw new InvalidSchemaError(e);
		}
		TraceObjectValue value = open.trace.getObjectManager()
				.createRootObject(ctx.getSchema(new SchemaName(req.getRootSchema())));
		return ReplyCreateObject.newBuilder().setObject(makeObjSpec(value.getChild())).build();
	}

	protected ReplyCreateTrace handleCreateTrace(RequestCreateTrace req)
			throws InvalidNameException, IOException, CancelledException {
		DomainFolder traces = getOrCreateNewTracesFolder();
		List<String> path = sanitizePath(req.getPath().getPath());
		DomainFolder folder = createFolders(traces, path.subList(0, path.size() - 1));
		CompilerSpec cs = requireCompilerSpec(req.getLanguage(), req.getCompiler());
		DBTrace trace = new DBTrace(path.get(path.size() - 1), cs, this);
		TraceRmiTarget target = new TraceRmiTarget(plugin.getTool(), this, trace);
		DoId doId = requireAvailableDoId(req.getOid());
		openTraces.put(new OpenTrace(doId, trace, target));
		createDeconflictedFile(folder, trace);
		return ReplyCreateTrace.getDefaultInstance();
	}

	protected static List<String> sanitizePath(String path) {
		return Stream.of(path.split("\\\\|/")).filter(p -> !p.isBlank()).toList();
	}

	protected ReplyDeleteBytes handleDeleteBytes(RequestDeleteBytes req)
			throws AddressOverflowException {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();
		AddressRange range = open.toRange(req.getRange(), false);
		if (range == null) {
			return ReplyDeleteBytes.getDefaultInstance();
		}
		open.trace.getMemoryManager()
				.removeBytes(snap, range.getMinAddress(), (int) range.getLength());
		return ReplyDeleteBytes.getDefaultInstance();
	}

	protected ReplyDeleteRegisterValue handleDeleteRegisterValue(
			RequestDeleteRegisterValue req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();
		AddressSpace space = open.trace.getBaseAddressFactory().getAddressSpace(req.getSpace());
		if (space == null) {
			return ReplyDeleteRegisterValue.getDefaultInstance();
		}
		TraceMemorySpace ms = open.trace.getMemoryManager().getMemorySpace(space, false);
		if (ms == null) {
			return ReplyDeleteRegisterValue.getDefaultInstance();
		}
		for (String name : req.getNamesList()) {
			Register register = open.getRegister(name, false);
			if (register == null) {
				continue;
			}
			ms.removeValue(snap, register);
		}
		return ReplyDeleteRegisterValue.getDefaultInstance();
	}

	protected ReplyDisassemble handleDisassemble(RequestDisassemble req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();

		/**
		 * TODO: Is this composition of laziness upon laziness efficient enough?
		 * 
		 * <p>
		 * Can experiment with ordering of address-set-view "expression" to optimize early
		 * termination.
		 * 
		 * <p>
		 * Want addresses satisfying {@code known | (readOnly & everKnown)}
		 */
		TraceMemoryManager memoryManager = open.trace.getMemoryManager();
		AddressSetView readOnly =
			memoryManager.getRegionsAddressSetWith(snap, r -> !r.isWrite());
		AddressSetView everKnown = memoryManager.getAddressesWithState(Lifespan.since(snap),
			s -> s == TraceMemoryState.KNOWN);
		AddressSetView roEverKnown = new IntersectionAddressSetView(readOnly, everKnown);
		AddressSetView known =
			memoryManager.getAddressesWithState(snap, s -> s == TraceMemoryState.KNOWN);
		AddressSetView disassemblable =
			new AddressSet(new UnionAddressSetView(known, roEverKnown));

		Address start = open.toAddress(req.getStart(), true);
		TracePlatform host = open.trace.getPlatformManager().getHostPlatform();

		TraceDisassembleCommand dis = new TraceDisassembleCommand(host, start, disassemblable);
		dis.setInitialContext(DebuggerDisassemblerPlugin.deriveAlternativeDefaultContext(
			host.getLanguage(), host.getLanguage().getLanguageID(), start));

		TaskMonitor monitor = plugin.getTaskMonitor();
		dis.applyToTyped(open.trace.getFixedProgramView(snap), monitor);

		return ReplyDisassemble.newBuilder()
				.setLength(dis.getDisassembledAddressSet().getNumAddresses())
				.build();
	}

	protected ReplyEndTx handleEndTx(RequestEndTx req) {
		OpenTx tx = openTxes.remove(new Tid(new DoId(req.getOid()), req.getTxid().getId()));
		if (tx == null) {
			throw new InvalidTxIdError(req.getTxid().getId());
		}
		if (req.getAbort()) {
			Msg.error(this, "Back-end debugger aborted a transaction!");
			tx.tx.abortOnClose();
		}
		tx.tx.close();
		OpenTrace open = requireOpenTrace(tx.txId.doId);
		if (!tx.undoable) {
			open.trace.clearUndo();
		}
		// TODO: Check for other transactions on the same trace?
		open.trace.setEventsEnabled(true);
		return ReplyEndTx.getDefaultInstance();
	}

	protected ReplyGetObject handleGetObject(RequestGetObject req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		// If the client is checking for existence, and error indicates absence.
		TraceObject object = open.getObject(req.getObject(), true);
		return ReplyGetObject.newBuilder().setObject(makeObjDesc(object)).build();
	}

	protected ReplyGetValues handleGetValues(RequestGetValues req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		return ReplyGetValues.newBuilder()
				.addAllValues(open.trace.getObjectManager()
						.getValuePaths(toLifespan(req.getSpan()),
							toPathPattern(req.getPattern()))
						.map(TraceRmiHandler::makeValDesc)
						.sorted(Comparator.comparing(ValDesc::getKey))
						.toList())
				.build();
	}

	protected ReplyGetValues handleGetValuesIntersecting(
			RequestGetValuesIntersecting req) throws AddressOverflowException {
		OpenTrace open = requireOpenTrace(req.getOid());
		AddressRange range = open.toRange(req.getBox().getRange(), false);
		String key = req.getKey() == "" ? null : req.getKey();
		Collection<? extends TraceObjectValue> col = range == null
				? List.of()
				: open.trace.getObjectManager()
						.getValuesIntersecting(toLifespan(req.getBox().getSpan()), range, key);
		return ReplyGetValues.newBuilder()
				.addAllValues(col.stream().map(TraceRmiHandler::makeValDesc).toList())
				.build();
	}

	protected ReplyInsertObject handleInsertObject(RequestInsertObject req) {
		TraceObject obj = requireOpenTrace(req.getOid()).getObject(req.getObject(), true);
		TraceObjectValPath val =
			obj.insert(toLifespan(req.getSpan()), toResolution(req.getResolution()));
		Lifespan span = val.getEntryList()
				.stream()
				.map(TraceObjectValue::getLifespan)
				.reduce(Lifespan.ALL, Lifespan::intersect);
		return ReplyInsertObject.newBuilder()
				.setSpan(makeSpan(span))
				.build();
	}

	protected ReplyNegotiate handleNegotiate(RequestNegotiate req) {
		if (!VERSION.equals(req.getVersion())) {
			VersionMismatchError error = new VersionMismatchError(req.getVersion());
			negotiate.completeExceptionally(error);
			throw error;
		}
		for (Method m : req.getMethodsList()) {
			RemoteMethod rm = new RecordRemoteMethod(this, m.getName(),
				ActionName.name(m.getAction()),
				m.getDescription(), m.getParametersList()
						.stream()
						.collect(Collectors.toMap(MethodParameter::getName, this::makeParameter)),
				new SchemaName(m.getReturnType().getName()));
			methodRegistry.add(rm);
		}
		negotiate.complete(null);
		return ReplyNegotiate.getDefaultInstance();
	}

	protected ReplyPutBytes handlePutBytes(RequestPutBytes req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();
		Address start = open.toAddress(req.getStart(), true);

		int written = open.trace.getMemoryManager()
				.putBytes(snap, start, req.getData().asReadOnlyByteBuffer());

		return ReplyPutBytes.newBuilder().setWritten(written).build();
	}

	protected ReplyPutRegisterValue handlePutRegisterValue(RequestPutRegisterValue req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();
		AddressSpace space = open.getSpace(req.getSpace(), true);
		TraceMemorySpace ms = open.trace.getMemoryManager().getMemorySpace(space, true);
		ReplyPutRegisterValue.Builder rep = ReplyPutRegisterValue.newBuilder();
		for (RegVal rv : req.getValuesList()) {
			Register register = open.getRegister(rv.getName(), false);
			if (register == null) {
				Msg.trace(this, "Ignoring unrecognized register: " + rv.getName());
				rep.addSkippedNames(rv.getName());
				continue;
			}
			BigInteger value = new BigInteger(1, rv.getValue().toByteArray());
			ms.setValue(snap, new RegisterValue(register, value));
		}
		return ReplyPutRegisterValue.getDefaultInstance();
	}

	protected RecordRemoteParameter makeParameter(MethodParameter mp) {
		return new RecordRemoteParameter(this, mp.getName(), new SchemaName(mp.getType().getName()),
			mp.getRequired(), ot -> ot.toValue(mp.getDefaultValue()), mp.getDisplay(),
			mp.getDescription());
	}

	protected ReplyRemoveObject handleRemoveObject(RequestRemoveObject req) {
		TraceObject object = requireOpenTrace(req.getOid()).getObject(req.getObject(), false);
		if (object == null) {
			return ReplyRemoveObject.getDefaultInstance();
		}
		Lifespan lifespan = toLifespan(req.getSpan());
		if (req.getTree()) {
			object.removeTree(lifespan);
		}
		else {
			object.remove(lifespan);
		}
		return ReplyRemoveObject.getDefaultInstance();
	}

	protected ReplyRetainValues handleRetainValues(RequestRetainValues req) {
		// This is not a primitive DB operation, but should be more efficient server side.
		TraceObject object = requireOpenTrace(req.getOid()).getObject(req.getObject(), false);
		if (object == null) {
			return ReplyRetainValues.getDefaultInstance();
		}
		Lifespan span = toLifespan(req.getSpan());
		Collection<? extends TraceObjectValue> values = switch (req.getKinds()) {
			case VK_ELEMENTS -> object.getElements(span);
			case VK_ATTRIBUTES -> object.getAttributes(span);
			case VK_BOTH -> object.getValues(span);
			default -> throw new TraceRmiError("Protocol error: Invalid value kinds");
		};
		Set<String> keysToKeep = Set.copyOf(req.getKeysList());
		List<String> keysToDelete = values.stream()
				.map(v -> v.getEntryKey())
				.filter(k -> !keysToKeep.contains(k))
				.distinct()
				.toList();
		for (String key : keysToDelete) {
			object.setValue(span, key, null, ConflictResolution.TRUNCATE);
		}
		return ReplyRetainValues.getDefaultInstance();
	}

	protected ReplySaveTrace handleSaveTrace(RequestSaveTrace req)
			throws CancelledException, IOException {
		OpenTrace open = requireOpenTrace(req.getOid());
		open.trace.save("TraceRMI", plugin.getTaskMonitor());
		return ReplySaveTrace.getDefaultInstance();
	}

	protected ReplySetMemoryState handleSetMemoryState(RequestSetMemoryState req)
			throws AddressOverflowException {
		OpenTrace open = requireOpenTrace(req.getOid());
		long snap = req.getSnap().getSnap();
		AddressRange range = open.toRange(req.getRange(), true);
		TraceMemoryState state = toMemoryState(req.getState());

		open.trace.getMemoryManager().setState(snap, range, state);

		return ReplySetMemoryState.getDefaultInstance();
	}

	protected ReplySetValue handleSetValue(RequestSetValue req)
			throws AddressOverflowException {
		ValSpec value = req.getValue();
		OpenTrace open = requireOpenTrace(req.getOid());
		Object objVal = open.toValue(value.getValue());
		TraceObject object = open.getObject(value.getParent(), objVal != null);
		if (object == null) {
			// Implies request was to set value to null
			return ReplySetValue.newBuilder().setSpan(makeSpan(Lifespan.EMPTY)).build();
		}

		TraceObjectValue val = object.setValue(toLifespan(value.getSpan()), value.getKey(),
			objVal, toResolution(req.getResolution()));
		return ReplySetValue.newBuilder()
				.setSpan(makeSpan(val == null ? Lifespan.EMPTY : val.getLifespan()))
				.build();
	}

	protected ReplySnapshot handleSnapshot(RequestSnapshot req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		TraceSnapshot snapshot = open.createSnapshot(req.getSnap(), req.getDescription());
		if (!"".equals(req.getDatetime())) {
			Instant instant =
				DateTimeFormatter.ISO_INSTANT.parse(req.getDatetime()).query(Instant::from);
			snapshot.setRealTime(instant.toEpochMilli());
		}
		return ReplySnapshot.getDefaultInstance();
	}

	protected ReplyStartTx handleStartTx(RequestStartTx req) {
		OpenTrace open = requireOpenTrace(req.getOid());
		Tid tid = requireAvailableTid(open, req.getTxid());
		open.trace.setEventsEnabled(false);
		@SuppressWarnings("resource")
		OpenTx tx =
			new OpenTx(tid, open.trace.openTransaction(req.getDescription()), req.getUndoable());
		openTxes.put(tx.txId, tx);
		return ReplyStartTx.getDefaultInstance();
	}

	protected RootMessage.Builder handleXInvokeMethod(XReplyInvokeMethod xrep) {
		String error = xrep.getError();
		DefaultRemoteAsyncResult result;
		synchronized (xReqQueue) {
			result = xReqQueue.poll();
		}
		if (error.isEmpty()) {
			try {
				result.complete(result.decoder.toValue(xrep.getReturnValue()));
			}
			catch (Throwable e) {
				result.completeExceptionally(e);
			}
		}
		else {
			result.completeExceptionally(new TraceRmiError(error));
		}
		return null;
	}

	@Override
	public SocketAddress getRemoteAddress() {
		return socket.getRemoteSocketAddress();
	}

	@Override
	public DefaultRemoteMethodRegistry getMethods() {
		return methodRegistry;
	}

	protected OpenTrace getOpenTrace(Trace trace) {
		if (trace == null) {
			return null;
		}
		OpenTrace open = openTraces.getByTrace(trace);
		if (open == null) {
			throw new NoSuchElementException();
		}
		return open;
	}

	protected DefaultRemoteAsyncResult invoke(OpenTrace open, String methodName,
			Map<String, Object> arguments) {
		RootMessage.Builder req = RootMessage.newBuilder();
		XRequestInvokeMethod.Builder invoke = XRequestInvokeMethod.newBuilder()
				.setName(methodName)
				.addAllArguments(
					arguments.entrySet().stream().map(TraceRmiHandler::makeArgument).toList());
		DefaultRemoteAsyncResult result;
		if (open != null) {
			result = new DefaultRemoteAsyncResult(open);
			invoke.setOid(open.doId.toDomObjId());
		}
		else {
			result = new DefaultRemoteAsyncResult();
		}
		req.setXrequestInvokeMethod(invoke);
		synchronized (xReqQueue) {
			xReqQueue.offer(result);
			synchronized (out) {
				try {
					sendDelimited(out, req.build(), dbgSeq++);
				}
				catch (IOException e) {
					throw new TraceRmiError("Could not send request", e);
				}
			}
			return result;
		}
	}

	@Override
	public long getLastSnapshot(Trace trace) {
		OpenTrace byTrace = openTraces.getByTrace(trace);
		if (byTrace == null) {
			throw new NoSuchElementException();
		}
		TraceSnapshot lastSnapshot = byTrace.lastSnapshot;
		if (lastSnapshot == null) {
			return 0;
		}
		return lastSnapshot.getKey();
	}

	@Override
	public Trace waitForTrace(long timeoutMillis) throws TimeoutException {
		try {
			return openTraces.getFirstAsync().get(timeoutMillis, TimeUnit.MILLISECONDS).trace;
		}
		catch (InterruptedException | ExecutionException e) {
			throw new TraceRmiError(e);
		}
	}

	@Override
	public void forceCloseTrace(Trace trace) {
		OpenTrace open = openTraces.removeByTrace(trace);
		open.trace.release(this);
	}

	@Override
	public boolean isTarget(Trace trace) {
		return openTraces.getByTrace(trace) != null;
	}

	public void registerTerminals(Collection<TerminalSession> terminals) {
		synchronized (this.terminals) {
			this.terminals.addAll(terminals);
		}
	}
}
