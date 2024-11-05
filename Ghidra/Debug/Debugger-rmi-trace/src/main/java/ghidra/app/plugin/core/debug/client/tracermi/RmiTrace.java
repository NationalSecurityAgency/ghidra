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

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.app.plugin.core.debug.client.tracermi.RmiClient.RequestResult;
import ghidra.dbg.target.schema.SchemaContext;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.trace.model.Lifespan;
import ghidra.util.LockHold;
import ghidra.util.Msg;

public class RmiTrace {

	final RmiClient client;
	private final int id;
	private RequestResult createResult;

	private int nextTx = 0;
	private Object txLock = new Object();
	private ReadWriteLock snLock = new ReentrantReadWriteLock();

	private Set<String> overlays = new HashSet<>();
	private long currentSnap = -1;
	private boolean closed = false;

	public MemoryMapper memoryMapper;
	public RegisterMapper registerMapper;

	public RmiTrace(RmiClient client, int id, RequestResult createResult) {
		this.client = client;
		this.id = id;
		this.createResult = createResult;
	}

	public void checkResult(long timeoutMs)
			throws InterruptedException, ExecutionException, TimeoutException {
		createResult.get(timeoutMs, TimeUnit.MILLISECONDS);
	}

	public void close() {
		if (closed) {
			return;
		}
		client.closeTrace(id);
	}

	public void save() {
		client.saveTrace(id);
	}

	public RmiTransaction startTx(String description, boolean undoable) {
		int txid;
		synchronized (txLock) {
			txid = nextTx++;
		}
		client.startTx(id, description, undoable, txid);
		return new RmiTransaction(this, txid);
	}

	public RmiTransaction openTx(String description) {
		return startTx(description, false);
	}

	public void endTx(int txid, boolean abort) {
		client.endTx(id, txid, abort);
	}

	public long nextSnap() {
		try (LockHold hold = LockHold.lock(snLock.writeLock())) {
			return ++currentSnap;
		}
	}

	public long snapshot(String description, String datatime, Long snap) {
		if (datatime == null) {
			datatime = "";
		}
		if (snap == null) {
			snap = nextSnap();
		}
		client.snapshot(id, description, datatime, snap.intValue());
		return snap.longValue();
	}

	public long getSnap() {
		try (LockHold hold = LockHold.lock(snLock.readLock())) {
			return currentSnap;
		}
	}

	public void setSnap(long snap) {
		try (LockHold hold = LockHold.lock(snLock.writeLock())) {
			this.currentSnap = snap;
		}
	}

	public long snapOrCurrent(Long snap) {
		try (LockHold hold = LockHold.lock(snLock.readLock())) {
			return snap == null ? this.currentSnap : snap.longValue();
		}
	}

	public void createOverlaySpace(String base, String name) {
		if (overlays.contains(name)) {
			return;
		}
		client.createOverlaySpace(id, base, name);
	}

	public void createOverlaySpace(Address repl, Address orig) {
		createOverlaySpace(repl.getAddressSpace().getName(), orig.getAddressSpace().getName());
	}

	public void putBytes(Address addr, byte[] data, Long snap) {
		client.putBytes(id, snapOrCurrent(snap), addr, data);
	}

	public void setMemoryState(AddressRange range, MemoryState state, Long snap) {
		client.setMemoryState(id, snapOrCurrent(snap), range, state);
	}

	public void deleteBytes(AddressRange range, Long snap) {
		client.deleteBytes(id, snapOrCurrent(snap), range);
	}

	public void putRegisters(String ppath, RegisterValue[] values, Long snap) {
		client.putRegisters(id, snapOrCurrent(snap), ppath, values);
	}

	public void deleteRegisters(String ppath, String[] names, Long snap) {
		client.deleteRegisters(id, snapOrCurrent(snap), ppath, names);
	}

	public void createRootObject(SchemaContext schemaContext, String schema) {
		client.createRootObject(id, schemaContext, schema);
	}

	public RmiTraceObject createObject(String path) {
		RequestResult result = client.createObject(id, path);
		return new RmiTraceObject(this, path, result);
	}

	public RmiTraceObject createAndInsertObject(String path) {
		RmiTraceObject object = createObject(path);
		object.insert(currentSnap, null);
		return object;
	}

	long handleCreateObject(ReplyCreateObject reply) {
		return reply.getObject().getId();
	}

	public Void handleCreateTrace(ReplyCreateTrace reply) {
		return null;
	}

	public List<RmiTraceObjectValue> handleGetValues(ReplyGetValues reply) {
		List<RmiTraceObjectValue> result = new ArrayList<>();
		for (ValDesc d : reply.getValuesList()) {
			RmiTraceObject parent = proxyObject(d.getParent());
			Lifespan span = Lifespan.span(d.getSpan().getMin(), d.getSpan().getMax());
			Object value = client.argToObject(id, d.getValue());
			TargetObjectSchema schema = client.getSchema(client.argToType(d.getValue()));
			result.add(new RmiTraceObjectValue(parent, span, d.getKey(), value, schema));
		}
		return result;
	}

	public long handleDisassemble(ReplyDisassemble reply) {
		Msg.info(this, "Disassembled " + reply.getLength() + " bytes");
		return reply.getLength();
	}

	public void insertObject(String path) {
		Lifespan span = getLifespan();
		client.insertObject(id, path, span, Resolution.CR_ADJUST);
	}

	private Lifespan getLifespan() {
		try (LockHold hold = LockHold.lock(snLock.readLock())) {
			return Lifespan.nowOn(currentSnap);
		}
	}

	public void setValue(String ppath, String key, Object value) {
		Lifespan span = getLifespan();
		client.setValue(id, ppath, span, key, value, null);
	}

	public void retainValues(String ppath, Set<String> keys, ValueKinds kinds) {
		Lifespan span = getLifespan();
		client.retainValues(id, ppath, span, kinds, keys);
	}

	@SuppressWarnings("unchecked")
	private <T> T doSync(RequestResult r) {
		if (client.hasBatch()) {
			return null;
		}
		try {
			return (T) r.get();
		}
		catch (InterruptedException | ExecutionException e) {
			throw new RuntimeException(e);
		}
	}

	public RequestResult getValuesAsync(String pattern) {
		Lifespan span = getLifespan();
		return client.getValues(id, span, pattern);
	}

	public List<RmiTraceObjectValue> getValues(String pattern) {
		return doSync(getValuesAsync(pattern));
	}

	public RequestResult getValuesRngAsync(Address start, long length) {
		Lifespan span = getLifespan();
		try {
			AddressRange range = new AddressRangeImpl(start, length);
			return client.getValuesIntersecting(id, span, range, "");
		}
		catch (AddressOverflowException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	public List<RmiTraceObjectValue> getValuesRng(Address start, long length) {
		return doSync(getValuesRngAsync(start, length));
	}

	public void activate(String path) {
		if (path == null) {
			Msg.error(this, "Attempt to activate null");
			return;
		}
		client.activate(id, path);
	}

	public void disassemble(Address start, Long snap) {
		client.disassemble(id, snapOrCurrent(snap), start);
	}

	public XReplyInvokeMethod handleInvokeMethod(XRequestInvokeMethod req) {
		try (RmiTransaction tx = startTx("InvokeMethod", false)) {
			return client.handleInvokeMethod(id, req);
		}
	}

	private RmiTraceObject proxyObject(ObjDesc desc) {
		return client.proxyObjectPath(id, desc.getId(), desc.getPath().getPath());
	}

	public RmiTraceObject proxyObjectId(Long objectId) {
		return client.proxyObjectId(id, objectId);
	}

	public RmiTraceObject proxyObjectPath(String path) {
		return client.proxyObjectPath(id, path);
	}

	public RmiTraceObject proxyObjectPath(Long objectId, String path) {
		return client.proxyObjectPath(id, objectId, path);
	}

	public int getId() {
		return id;
	}

}
