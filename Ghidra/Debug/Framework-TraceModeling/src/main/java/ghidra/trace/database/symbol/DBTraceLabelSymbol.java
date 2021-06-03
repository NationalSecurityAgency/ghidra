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
package ghidra.trace.database.symbol;

import java.io.IOException;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.DBTraceUtils.AddressDBFieldCodec;
import ghidra.trace.database.DBTraceUtils.DecodesAddresses;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.TraceLabelSymbol;
import ghidra.trace.util.TraceAddressSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStore;
import ghidra.util.database.DBObjectColumn;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceLabelSymbol extends AbstractDBTraceSymbol
		implements TraceLabelSymbol, DBTraceSpaceKey, DecodesAddresses {
	static final String TABLE_NAME = "Labels";

	private static final byte PRIMARY_MASK = 0x10;
	private static final int PRIMARY_CLEAR = ~PRIMARY_MASK;

	static final String ADDRESS_COLUMN_NAME = "Address";
	static final String THREAD_COLUMN_NAME = "Thread";
	static final String START_SNAP_COLUMN_NAME = "Start";
	static final String END_SNAP_COLUMN_NAME = "End";

	@DBAnnotatedColumn(ADDRESS_COLUMN_NAME)
	static DBObjectColumn ADDRESS_COLUMN;
	@DBAnnotatedColumn(THREAD_COLUMN_NAME)
	static DBObjectColumn THREAD_COLUMN;
	@DBAnnotatedColumn(START_SNAP_COLUMN_NAME)
	static DBObjectColumn START_SNAP_COLUMN;
	@DBAnnotatedColumn(END_SNAP_COLUMN_NAME)
	static DBObjectColumn END_SNAP_COLUMN;

	@DBAnnotatedField(column = ADDRESS_COLUMN_NAME, codec = AddressDBFieldCodec.class)
	protected Address address; // NOTE: Indexed in manager's range map
	@DBAnnotatedField(column = THREAD_COLUMN_NAME)
	protected long threadKey;
	@DBAnnotatedField(column = START_SNAP_COLUMN_NAME)
	protected long startSnap;
	@DBAnnotatedField(column = END_SNAP_COLUMN_NAME)
	protected long endSnap;

	protected DBTraceThread thread;
	protected Range<Long> lifespan;

	public DBTraceLabelSymbol(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(manager, store, record);
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}

		thread = manager.threadManager.getThread(threadKey);
		lifespan = DBTraceUtils.toRange(startSnap, endSnap);
	}

	protected void set(Range<Long> lifespan, DBTraceThread thread, Address address, String name,
			DBTraceNamespaceSymbol parent, SourceType source) {
		this.name = name;
		this.parentID = parent.getID();
		doSetSource(source);
		this.address = address;
		this.threadKey = thread == null ? -1 : thread.getKey();
		this.startSnap = DBTraceUtils.lowerEndpoint(lifespan);
		this.endSnap = DBTraceUtils.upperEndpoint(lifespan);

		update(NAME_COLUMN, PARENT_COLUMN, START_SNAP_COLUMN, END_SNAP_COLUMN, FLAGS_COLUMN,
			ADDRESS_COLUMN, THREAD_COLUMN);

		this.parent = parent;
		this.thread = thread;
		this.lifespan = lifespan;
	}

	@Override
	public Address decodeAddress(int spaceId, long offset) {
		return manager.trace.getBaseAddressFactory().getAddress(spaceId, offset);
	}

	@Override
	public Range<Long> getLifespan() {
		return lifespan;
	}

	@Override
	public long getStartSnap() {
		return startSnap;
	}

	@Override
	public void setEndSnap(long endSnap) {
		if (this.endSnap == endSnap) {
			return;
		}
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			Range<Long> newLifespan = DBTraceUtils.toRange(startSnap, endSnap);
			this.endSnap = endSnap;
			update(END_SNAP_COLUMN);

			Range<Long> oldLifespan = lifespan;
			this.lifespan = newLifespan;

			manager.trace.setChanged(new TraceChangeRecord<>(TraceSymbolChangeType.LIFESPAN_CHANGED,
				getSpace(), this, oldLifespan, newLifespan));
		}
	}

	@Override
	public long getEndSnap() {
		return endSnap;
	}

	@Override
	public AddressSpace getAddressSpace() {
		return address.getAddressSpace();
	}

	@Override
	public DBTraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return 0;
	}

	@Override
	protected TraceAddressSpace getSpace() {
		return this;
	}

	@Override
	public SymbolType getSymbolType() {
		return SymbolType.LABEL;
	}

	@Override
	protected void validateNameAndParent(String newName, DBTraceNamespaceSymbol newParent)
			throws DuplicateNameException {
		manager.assertNotDuplicate(this, lifespan, thread, address, newName, newParent);
	}

	@Override
	public Address getAddress() {
		return address;
	}

	@Override
	public DBTraceCodeUnitAdapter getCodeUnit() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			DBTraceCodeSpace code = manager.trace.getCodeManager().get(this, false);
			if (code == null) {
				return manager.trace.getCodeManager()
						.doCreateUndefinedUnit(startSnap, address, thread, getFrameLevel());
			}
			DBTraceCodeUnitAdapter cu = code.codeUnits().getContaining(startSnap, address);
			if (cu == null) {
				return cu;
			}
			if (address.equals(cu.getMinAddress())) {
				return cu;
			}
			if (cu instanceof DBTraceDataAdapter) {
				int offset = (int) address.subtract(cu.getMinAddress());
				DBTraceDataAdapter data = ((DBTraceDataAdapter) cu).getPrimitiveAt(offset);
				return data == null ? cu : data;
			}
			return null;
		}
	}

	@Override
	public Object getObject() {
		return getCodeUnit();
	}

	/**
	 * Set the primary flag.
	 * 
	 * The caller must still call {@link #update(DBObjectColumn...)} for {@link #FLAGS_COLUMN}, if
	 * this method returns true.
	 * 
	 * @return true if the primary flag was modified.
	 */
	protected boolean doSetPrimary(boolean primary) {
		boolean old = isPrimary();
		if (primary == old) {
			return false;
		}
		if (primary) {
			flags |= PRIMARY_MASK;
		}
		else {
			flags &= PRIMARY_CLEAR;
		}
		return true;
	}

	@Override
	public boolean setPrimary() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			AddressRangeImpl range = new AddressRangeImpl(address, address);
			if (!manager.functions.getIntersecting(lifespan, thread, range, false,
				true).isEmpty()) {
				// Labels cannot supersede a function
				return false;
			}
			boolean result = doSetPrimary(true);
			if (!result) {
				return false;
			}

			// TODO: May be able to resolve "multiple overlapping primary" with priority instead
			boolean firedEvent = false;
			update(FLAGS_COLUMN);
			for (DBTraceLabelSymbol other : manager.labels.getIntersecting(lifespan, thread, range,
				false, true)) {
				if (other.doSetPrimary(false)) {
					other.update(AbstractDBTraceSymbol.FLAGS_COLUMN);
					manager.trace.setChanged(new TraceChangeRecord<>(
						TraceSymbolChangeType.SET_AS_PRIMARY, getSpace(), this, other, this));
					firedEvent = true;
				}
			}
			if (!firedEvent) {
				manager.trace.setChanged(new TraceChangeRecord<>(
					TraceSymbolChangeType.SET_AS_PRIMARY, getSpace(), this));
			}
			return true;
		}
	}

	@Override
	public boolean isPrimary() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return (flags & PRIMARY_MASK) != 0;
		}
	}
}
