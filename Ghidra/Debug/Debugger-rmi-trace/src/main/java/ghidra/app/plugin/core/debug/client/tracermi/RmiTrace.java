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

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import ghidra.dbg.target.schema.SchemaContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.RegisterValue;
import ghidra.rmi.trace.TraceRmi.*;
import ghidra.trace.model.Lifespan;
import ghidra.util.LockHold;
import ghidra.util.Msg;

public class RmiTrace {
	
	final RmiClient client;
	private final int id;
	
	private int nextTx = 0;
	private Object txLock = new Object();
	private ReadWriteLock snLock = new ReentrantReadWriteLock();
	
	private Set<String> overlays = new HashSet<>();
	private long currentSnap = -1;
	private boolean closed = false;

	public MemoryMapper memoryMapper;
	public RegisterMapper registerMapper;

	public RmiTrace(RmiClient client, int id) {
		this.client = client;
		this.id = id;	
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
		synchronized(txLock) {
			txid = nextTx++;
		}
		client.startTx(id, description, undoable, txid);
		return new RmiTransaction(this, txid);
	}

	public RmiTransaction openTx(String description) {
		return startTx(description, false);
	}

	public void endTx(int txid, boolean abort)  {
		client.endTx(id, txid, abort);
	}
	
	public long nextSnap() {
		try (LockHold hold = LockHold.lock(snLock.writeLock())) {
			return ++currentSnap;
		}
	}
	
	public long snapshot(String description, String datatime, Long snap) {
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

	public void putBytes(Address addr, byte[]  data, Long snap)  {
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
	
	public void createObject(String path) {
		client.createObject(id, path);
	}

	public void handleCreateObject(ReplyCreateObject reply) {
		RmiTraceObject obj = new RmiTraceObject(this, reply.getObject());
	    try (RmiTransaction tx = startTx("CreateObject", false); LockHold hold = LockHold.lock(snLock.readLock())) {
			obj.insert(currentSnap, null);
	    }
	}
	
	public void handleCreateTrace(ReplyCreateTrace reply) {
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
	
	public void activate(String path) {
		if (path == null) {
			Msg.error(this, "Attempt to activate null");
		}
		client.activate(id, path);
	}
	
	public void disassemble(Address start, Long snap)  {
		client.disassemble(id, snapOrCurrent(snap), start);
	}
	
	public void handleInvokeMethod(XRequestInvokeMethod req) {
	    try (RmiTransaction tx = startTx("InvokeMethod", false)) {
	    	client.handleInvokeMethod(id, req);
	    }
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
