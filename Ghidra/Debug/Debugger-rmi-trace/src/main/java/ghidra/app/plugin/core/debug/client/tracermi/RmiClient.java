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
package ghidra.app.plugin.core.debug.client.tracermi;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Parameter;
import java.nio.channels.SocketChannel;
import java.util.*;

import org.jdom.JDOMException;

import com.google.protobuf.ByteString;

import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.rmi.trace.TraceRmi;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.rmi.trace.TraceRmi.Language;
import ghidra.rmi.trace.TraceRmi.Value.Builder;
import ghidra.trace.model.Lifespan;
import ghidra.util.Msg;

public class RmiClient {
	private final ProtobufSocket<RootMessage> socket;
	private final String description;
	private int nextTraceId = 0;
	private RmiBatch currentBatch = null;

	Map<Integer, RmiTrace> traces = new HashMap<>();
	private SchemaContext schemaContext;
	private RmiMethodHandlerThread handler;
	private static RmiMethodRegistry methodRegistry;
	private Deque<RootMessage> requests = new LinkedList<>();

	public static TargetObjectSchema loadSchema(String resourceName, String rootName) {
		XmlSchemaContext schemaContext;

		try {
			InputStream resourceAsStream = RmiClient.class.getResourceAsStream(resourceName);
			schemaContext = XmlSchemaContext
					.deserialize(resourceAsStream);
			return schemaContext.getSchema(schemaContext.name(rootName));
		}
		catch (JDOMException | IOException e) {
			throw new AssertionError(e);
		}
	}

//	public static TargetObjectSchema getSchema(String name) {
//		try {
//			return SCHEMA_CTX.getSchema(new SchemaName(name));
//		} catch (NullPointerException e) {
//			System.err.println("Possibly non-existent schema: "+name);
//			return SCHEMA_CTX.getSchema(new SchemaName("OBJECT"));
//		}
//	}

	public static enum TraceRmiResolution {
		RES_ADJUST("adjust", Resolution.CR_ADJUST), //
		RES_DENY("deny", Resolution.CR_DENY), //
		RES_TRUNCATE("truncate", Resolution.CR_TRUNCATE), //
		;

		TraceRmiResolution(String val, TraceRmi.Resolution description) {
			this.val = val;
			this.description = description;
		}

		public final String val;
		public final Resolution description;
	}

	public static enum TraceRmiValueKinds {
		ATTRIBUTES("attributes", ValueKinds.VK_ATTRIBUTES), //
		ELEMENTS("elements", ValueKinds.VK_ELEMENTS), //
		BOTH("both", ValueKinds.VK_BOTH), //
		;

		TraceRmiValueKinds(String val, TraceRmi.ValueKinds description) {
			this.val = val;
			this.description = description;
		}

		public final String val;
		public final ValueKinds description;
	}

	public RmiClient(SocketChannel channel, String description) {
		this.socket = new ProtobufSocket<>(channel, RootMessage::parseFrom);
		this.description = description;
		this.handler = new RmiMethodHandlerThread(this, socket);
		handler.start();
	}

	public ProtobufSocket<RootMessage> getSocket() {
		return socket;
	}

	public String getDescription() {
		return description;
	}

	public void close() {
		handler.close();
		socket.close();
	}

	private void send(RootMessage msg) {
		try {
			requests.push(msg);
			socket.send(msg);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public RmiTrace createTrace(String path, LanguageID language, CompilerSpecID compiler) {
		if (compiler == null) {
			compiler = new CompilerSpecID("default");
		}
		RmiTrace trace = new RmiTrace(this, nextTraceId);
		traces.put(nextTraceId, trace);
		send(RootMessage.newBuilder()
				.setRequestCreateTrace(RequestCreateTrace.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(nextTraceId++))
						.setLanguage(Language.newBuilder()
								.setId(language.getIdAsString()))
						.setCompiler(Compiler.newBuilder()
								.setId(compiler.getIdAsString()))
						.setPath(FilePath.newBuilder()
								.setPath(path)))
				.build());
		return trace;
	}

	public void closeTrace(int id) {
		send(RootMessage.newBuilder()
				.setRequestCloseTrace(RequestCloseTrace.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(id)))
				.build());
	}

	public void saveTrace(int id) {
		send(RootMessage.newBuilder()
				.setRequestSaveTrace(RequestSaveTrace.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(id)))
				.build());
	}

	public void startTx(int traceId, String desc, boolean undoable, int txId) {
		send(RootMessage.newBuilder()
				.setRequestStartTx(RequestStartTx.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setTxid(TxId.newBuilder().setId(txId))
						.setDescription(desc)
						.setUndoable(undoable))
				.build());
	}

	public void endTx(int traceId, int txId, boolean abort) {
		send(RootMessage.newBuilder()
				.setRequestEndTx(RequestEndTx.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setTxid(TxId.newBuilder().setId(txId))
						.setAbort(abort))
				.build());
	}

	public void snapshot(int traceId, String desc, String datetime, long snap) {
		send(RootMessage.newBuilder()
				.setRequestSnapshot(RequestSnapshot.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder()
								.setSnap(snap))
						.setDatetime(datetime)
						.setDescription(desc))
				.build());
	}

	public void createOverlaySpace(int traceId, String base, String name) {
		send(RootMessage.newBuilder()
				.setRequestCreateOverlay(RequestCreateOverlaySpace.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setBaseSpace(base)
						.setName(name))
				.build());
	}

	public void putBytes(int traceId, long snap, Address start, byte[] data) {
		send(RootMessage.newBuilder()
				.setRequestPutBytes(RequestPutBytes.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder().setSnap(snap))
						.setStart(Addr.newBuilder()
								.setSpace(start.getAddressSpace().getName())
								.setOffset(start.getOffset()))
						.setData(ByteString.copyFrom(data)))
				.build());
	}

	public void setMemoryState(int traceId, long snap, AddressRange range, MemoryState state) {
		send(RootMessage.newBuilder()
				.setRequestSetMemoryState(RequestSetMemoryState.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder().setSnap(snap))
						.setRange(AddrRange.newBuilder()
								.setSpace(range.getAddressSpace().getName())
								.setOffset(range.getMinAddress().getOffset())
								.setExtend(range.getLength() - 1))
						.setState(state))
				.build());
	}

	public void deleteBytes(int traceId, long snap, AddressRange range) {
		send(RootMessage.newBuilder()
				.setRequestDeleteBytes(RequestDeleteBytes.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder().setSnap(snap))
						.setRange(AddrRange.newBuilder()
								.setSpace(range.getAddressSpace().getName())
								.setOffset(range.getMinAddress().getOffset())
								.setExtend(range.getLength())))
				.build());
	}

	public void putRegisters(int traceId, long snap, String ppath, RegisterValue[] values) {
		RequestPutRegisterValue.Builder builder = RequestPutRegisterValue.newBuilder()
				.setOid(DomObjId.newBuilder()
						.setId(traceId))
				.setSnap(Snap.newBuilder().setSnap(snap))
				.setSpace(ppath);
		for (int i = 0; i < values.length; i++) {
			RegisterValue rv = values[i];
			ByteString val = ByteString.copyFrom(rv.toBytes());
			rv.getUnsignedValue();
			builder.addValues(i, RegVal.newBuilder()
					.setName(rv.getRegister().getName())
					.setValue(val));
		}
		send(RootMessage.newBuilder()
				.setRequestPutRegisterValue(builder)
				.build());
	}

	public void deleteRegisters(int traceId, long snap, String ppath, String[] names) {
		RequestDeleteRegisterValue.Builder builder = RequestDeleteRegisterValue.newBuilder()
				.setOid(DomObjId.newBuilder()
						.setId(traceId))
				.setSnap(Snap.newBuilder().setSnap(snap))
				.setSpace(ppath);
		for (int i = 0; i < names.length; i++) {
			String name = names[i];
			builder.setNames(i, name);
		}
		send(RootMessage.newBuilder()
				.setRequestDeleteRegisterValue(builder)
				.build());
	}

	public void createRootObject(int traceId, SchemaContext schemContext, String schema) {
		this.schemaContext = schemContext;
		String xmlCtx = XmlSchemaContext.serialize(schemContext);
		send(RootMessage.newBuilder()
				.setRequestCreateRootObject(RequestCreateRootObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSchemaContext(xmlCtx)
						.setRootSchema(schema))
				.build());
	}

	public void createObject(int traceId, String path) {
		//System.err.println("createObject:"+path);
		send(RootMessage.newBuilder()
				.setRequestCreateObject(RequestCreateObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setPath(ObjPath.newBuilder().setPath(path)))
				.build());
	}

	public void insertObject(int traceId, String path, Lifespan span, Resolution r) {
		send(RootMessage.newBuilder()
				.setRequestInsertObject(RequestInsertObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setObject(ObjSpec.newBuilder()
								.setPath(ObjPath.newBuilder()
										.setPath(path)))
						.setSpan(Span.newBuilder()
								.setMin(span.lmin())
								.setMax(span.lmax()))
						.setResolution(r))
				.build());
	}

	public void insertObject(int traceId, ObjSpec object, Lifespan span, Resolution r) {
		send(RootMessage.newBuilder()
				.setRequestInsertObject(RequestInsertObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setObject(object)
						.setSpan(Span.newBuilder()
								.setMin(span.lmin())
								.setMax(span.lmax()))
						.setResolution(r))
				.build());
	}

	public void removeObject(int traceId, ObjSpec object, Lifespan span, boolean tree) {
		send(RootMessage.newBuilder()
				.setRequestRemoveObject(RequestRemoveObject.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setObject(object)
						.setSpan(Span.newBuilder()
								.setMin(span.lmin())
								.setMax(span.lmax()))
						.setTree(tree))
				.build());
	}

	public void setValue(int traceId, String ppath, Lifespan span, String key, Object value,
			String resolution) {
		Resolution r = resolution == null ? Resolution.CR_ADJUST
				: TraceRmiResolution.valueOf(resolution).description;
		send(RootMessage.newBuilder()
				.setRequestSetValue(RequestSetValue.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setValue(ValSpec.newBuilder()
								.setSpan(Span.newBuilder()
										.setMin(span.lmin())
										.setMax(span.lmax()))
								.setParent(ObjSpec.newBuilder()
										.setPath(ObjPath.newBuilder()
												.setPath(ppath)))
								.setKey(key)
								.setValue(buildValue(value)))
						.setResolution(r))
				.build());
	}

	public void retainValues(int traceId, String ppath, Lifespan span, ValueKinds kinds,
			Set<String> keys) {
		RequestRetainValues.Builder builder = RequestRetainValues.newBuilder()
				.setOid(DomObjId.newBuilder()
						.setId(traceId))
				.setObject(ObjSpec.newBuilder()
						.setPath(ObjPath.newBuilder()
								.setPath(ppath)))
				.setSpan(Span.newBuilder()
						.setMin(span.lmin())
						.setMax(span.lmax()))
				.setKinds(kinds)
				.addAllKeys(keys);
		send(RootMessage.newBuilder()
				.setRequestRetainValues(builder)
				.build());
	}

	public void getObject(int traceId, String path) {
		RequestGetObject.Builder builder = RequestGetObject.newBuilder()
				.setOid(DomObjId.newBuilder()
						.setId(traceId))
				.setObject(ObjSpec.newBuilder()
						.setPath(ObjPath.newBuilder()
								.setPath(path)));
		send(RootMessage.newBuilder()
				.setRequestGetObject(builder)
				.build());
	}

	public void getValues(int traceId, Lifespan span, String pattern) {
		send(RootMessage.newBuilder()
				.setRequestGetValues(RequestGetValues.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSpan(Span.newBuilder()
								.setMin(span.lmin())
								.setMax(span.lmax()))
						.setPattern(ObjPath.newBuilder().setPath(pattern)))
				.build());
	}

	public void getValuesIntersecting(int traceId, Lifespan span, AddressRange range,
			String key) {
		send(RootMessage.newBuilder()
				.setRequestGetValuesIntersecting(RequestGetValuesIntersecting.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setBox(Box.newBuilder()
								.setSpan(Span.newBuilder()
										.setMin(span.lmin())
										.setMax(span.lmax()))
								.setRange(AddrRange.newBuilder()
										.setSpace(range.getAddressSpace().getName())
										.setOffset(range.getMinAddress().getOffset())
										.setExtend(range.getLength())))
						.setKey(key))
				.build());
	}

	public RmiTraceObject proxyObjectId(int traceId, Long id) {
		return RmiTraceObject.fromId(traces.get(traceId), id);
	}

	public RmiTraceObject proxyObjectPath(int traceId, String path) {
		return RmiTraceObject.fromPath(traces.get(traceId), path);
	}

	public RmiTraceObject proxyObjectPath(int traceId, Long id, String path) {
		return new RmiTraceObject(traces.get(traceId), id, path);
	}

	@SuppressWarnings("unchecked")
	private Builder buildValue(Object value) {
		Builder builder = Value.newBuilder();
		if (value instanceof String str) {
			return builder.setStringValue(str);
		}
		if (value instanceof Boolean bval) {
			return builder.setBoolValue(bval);
		}
		if (value instanceof Short sval) {
			return builder.setShortValue(sval);
		}
		if (value instanceof Integer ival) {
			return builder.setIntValue(ival);
		}
		if (value instanceof Long lval) {
			return builder.setLongValue(lval);
		}
		if (value instanceof ByteString bstr) {
			return builder.setBytesValue(bstr);
		}
		if (value instanceof Byte b) {
			return builder.setByteValue(b);
		}
		if (value instanceof Character c) {
			return builder.setCharValue(c);
		}
		if (value instanceof Address address) {
			Addr.Builder addr = Addr.newBuilder()
					.setSpace(address.getAddressSpace().getName())
					.setOffset(address.getOffset());
			return builder.setAddressValue(addr);
		}
		if (value instanceof AddressRange range) {
			AddrRange.Builder rng = AddrRange.newBuilder()
					.setSpace(range.getAddressSpace().getName())
					.setOffset(range.getMinAddress().getOffset())
					.setExtend(range.getLength() - 1);
			return builder.setRangeValue(rng);
		}
		if (value instanceof RmiTraceObject obj) {
			return builder.setChildSpec(ObjSpec.newBuilder()
					.setPath(ObjPath.newBuilder()
							.setPath(obj.getPath())));
		}
		if (value instanceof List<?> list) {
			if (list.get(0) instanceof String) {
				StringArr.Builder b = StringArr.newBuilder().addAllArr((List<String>) list);
				return builder.setStringArrValue(b.build());
			}
			if (list.get(0) instanceof Boolean) {
				BoolArr.Builder b = BoolArr.newBuilder().addAllArr((List<Boolean>) list);
				return builder.setBoolArrValue(b.build());
			}
			if (list.get(0) instanceof Short) {
				ShortArr.Builder b = ShortArr.newBuilder().addAllArr((List<Integer>) list);
				return builder.setShortArrValue(b.build());
			}
			if (list.get(0) instanceof Integer) {
				IntArr.Builder b = IntArr.newBuilder().addAllArr((List<Integer>) list);
				return builder.setIntArrValue(b.build());
			}
			if (list.get(0) instanceof Long) {
				LongArr.Builder b = LongArr.newBuilder().addAllArr((List<Long>) list);
				return builder.setLongArrValue(b.build());
			}
		}

		throw new RuntimeException("Unhandled type for buildValue: " + value);
	}

	public void activate(int traceId, String path) {
		send(RootMessage.newBuilder()
				.setRequestActivate(RequestActivate.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setObject(ObjSpec.newBuilder()
								.setPath(ObjPath.newBuilder()
										.setPath(path))))
				.build());
	}

	public void disassemble(int traceId, long snap, Address start) {
		send(RootMessage.newBuilder()
				.setRequestDisassemble(RequestDisassemble.newBuilder()
						.setOid(DomObjId.newBuilder()
								.setId(traceId))
						.setSnap(Snap.newBuilder().setSnap(snap))
						.setStart(Addr.newBuilder()
								.setSpace(start.getAddressSpace().getName())
								.setOffset(start.getOffset())))
				.build());
	}

	public void negotiate(String desc) {
		RequestNegotiate.Builder builder = RequestNegotiate.newBuilder()
				.setVersion(TraceRmiHandler.VERSION)
				.setDescription(desc);
		int i = 0;
		for (RmiRemoteMethod m : methodRegistry.getMap().values()) {
			Method method = buildMethod(m);
			builder.addMethods(i++, method);
		}
		send(RootMessage.newBuilder()
				.setRequestNegotiate(builder)
				.build());
	}

	private Method buildMethod(RmiRemoteMethod method) {
		Method.Builder builder = Method.newBuilder()
				.setName(method.getName())
				.setDescription(method.getDescription())
				.setAction(method.getAction())
				.setDisplay(method.getDisplay());
		int i = 0;
		for (RmiRemoteMethodParameter p : method.getParameters()) {
			MethodParameter param = buildParameter(p);
			builder.addParameters(i++, param);
		}
		return builder.build();
	}

	private MethodParameter buildParameter(RmiRemoteMethodParameter param) {
		return MethodParameter.newBuilder()
				.setName(param.getName())
				.setDisplay(param.getDisplay())
				.setDescription(param.getDescription())
				.setType(param.getType())
				.setDefaultValue(param.getDefaultValue())
				.setRequired(param.isRequired())
				.build();
	}

	public void handleInvokeMethod(int traceId, XRequestInvokeMethod req) {
		RmiRemoteMethod rm = getMethod(req.getName());
		Object[] arglist = new Object[req.getArgumentsCount()];
		java.lang.reflect.Method m = rm.getMethod();
		Map<String, MethodArgument> argmap = new HashMap<>();
		for (int i = 0; i < req.getArgumentsCount(); i++) {
			MethodArgument arg = req.getArguments(i);
			argmap.put(arg.getName(), arg);
		}
		int i = 0;
		for (Parameter p : m.getParameters()) {
			MethodArgument arg = argmap.get(p.getName());
			if (arg != null) {
				Object obj = argToObject(traceId, arg);
				arglist[i++] = obj;
			}
		}
		try {
			Object ret = m.invoke(rm.getContainer(), arglist);
			if (ret != null) {
				socket.send(RootMessage.newBuilder()
						.setXreplyInvokeMethod(XReplyInvokeMethod.newBuilder()
								.setReturnValue(buildValue(ret)))
						.build());
			}
		}
		catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| IOException e) {
			String message = e.getMessage();
			if (message != null) {
				Msg.error(this, message);
				try {
					socket.send(RootMessage.newBuilder()
							.setXreplyInvokeMethod(
								XReplyInvokeMethod.newBuilder().setError(message))
							.build());
				}
				catch (IOException e1) {
					Msg.error(this, e1.getMessage());
				}
			}
		}

	}

	private Object argToObject(int traceId, MethodArgument arg) {
		if (arg == null) {
			throw new RuntimeException("Null argument passed to argToObject");
		}
		Value value = arg.getValue();
		if (value.hasStringValue()) {
			return value.getStringValue();
		}
		if (value.hasStringArrValue()) {
			return value.getStringArrValue();
		}
		if (value.hasBoolValue()) {
			return value.getBoolValue();
		}
		if (value.hasBoolArrValue()) {
			return value.getBoolArrValue();
		}
		if (value.hasCharValue()) {
			return value.getCharValue();
		}
		if (value.hasCharArrValue()) {
			return value.getCharArrValue();
		}
		if (value.hasShortValue()) {
			return value.getShortValue();
		}
		if (value.hasShortArrValue()) {
			return value.getShortArrValue();
		}
		if (value.hasIntValue()) {
			return value.getIntValue();
		}
		if (value.hasIntArrValue()) {
			return value.getIntArrValue();
		}
		if (value.hasLongValue()) {
			return value.getLongValue();
		}
		if (value.hasLongArrValue()) {
			return value.getLongArrValue();
		}
		if (value.hasAddressValue()) {
			return decodeAddr(traceId, value.getAddressValue());
		}
		if (value.hasRangeValue()) {
			return decodeRange(traceId, value.getRangeValue());
		}
		if (value.hasByteValue()) {
			return value.getByteValue();
		}
		if (value.hasBytesValue()) {
			return value.getBytesValue();
		}
		if (value.hasNullValue()) {
			return value.getNullValue();
		}
		ObjDesc desc = value.getChildDesc();
		String path = desc.getPath().getPath();
		return proxyObjectPath(traceId, path);
	}

	private Address decodeAddr(int id, Addr addr) {
		RmiTrace trace = traces.get(id);
		return trace.memoryMapper.genAddr(addr.getSpace(), addr.getOffset());
	}

	private AddressRange decodeRange(int id, AddrRange rng) {
		RmiTrace trace = traces.get(id);
		Address start = trace.memoryMapper.genAddr(rng.getSpace(), rng.getOffset());
		return new AddressRangeImpl(start, start.add(rng.getExtend()));
	}

	public void setRegistry(RmiMethodRegistry methodRegistry) {
		RmiClient.methodRegistry = methodRegistry;
	}

	public RmiRemoteMethod getMethod(String name) {
		return methodRegistry.getMap().get(name);
	}

	public Object startBatch() {
		if (currentBatch == null) {
			currentBatch = new RmiBatch();
		}
		currentBatch.inc();
		return currentBatch;
	}

	public Object endBatch() {
		RmiBatch cb = null;
		if (0 == currentBatch.dec()) {
			cb = currentBatch;
			currentBatch = null;
		}
		if (cb != null) {
			return cb.results();
		}
		return null;
	}

	public TargetObjectSchema getSchema(String schema) {
		return schemaContext.getSchema(new SchemaName(schema));
	}

	public RootMessage getRequestsPoll() {
		return requests.poll();
	}

}
