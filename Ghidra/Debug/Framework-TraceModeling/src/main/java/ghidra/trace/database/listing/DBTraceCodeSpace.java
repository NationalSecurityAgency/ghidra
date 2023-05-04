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
package ghidra.trace.database.listing;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;

import db.DBHandle;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Dynamic;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.data.DBTraceDataTypeManager;
import ghidra.trace.database.guest.DBTraceGuestPlatform;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry;
import ghidra.trace.database.space.DBTraceSpaceBased;
import ghidra.trace.database.symbol.DBTraceReferenceManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceCodeManager;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.ByteArrayUtils;
import ghidra.util.LockHold;
import ghidra.util.database.DBCachedObjectStoreFactory;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * A space managed by the {@link DBTraceCodeManager}
 * 
 * <p>
 * This implements {@link TraceCodeManager#getCodeSpace(AddressSpace, boolean)} and
 * {@link TraceCodeManager#getCodeRegisterSpace(TraceThread, int, boolean)}.
 */
public class DBTraceCodeSpace implements TraceCodeSpace, DBTraceSpaceBased {
	protected final DBTraceCodeManager manager;
	protected final DBHandle dbh;
	protected final AddressSpace space;
	protected final TraceThread thread;
	protected final int frameLevel;
	protected final ReadWriteLock lock;
	protected final Language baseLanguage;
	protected final DBTrace trace;
	protected final DBTraceDataTypeManager dataTypeManager;
	protected final DBTraceReferenceManager referenceManager;
	protected final AddressRange all;

	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceInstruction, DBTraceInstruction> instructionMapSpace;
	protected final DBTraceAddressSnapRangePropertyMapSpace<DBTraceData, DBTraceData> dataMapSpace;

	// NOTE: All combinations except () and (INSTRUCTIONS,UNDEFINED)
	protected DBTraceInstructionsView instructions;
	protected DBTraceDefinedDataView definedData;
	protected DBTraceUndefinedDataView undefinedData;
	protected DBTraceDataView data;
	protected DBTraceDefinedUnitsView definedUnits;
	protected DBTraceCodeUnitsView codeUnits;

	/**
	 * Construct a space
	 * 
	 * @param manager the manager
	 * @param dbh the database handle
	 * @param space the address space
	 * @param ent an entry describing this space
	 * @param thread a thread, if applicable, for a per-thread/frame space
	 * @throws VersionException if there is already a table of a different version
	 * @throws IOException if there is trouble accessing the database
	 */
	public DBTraceCodeSpace(DBTraceCodeManager manager, DBHandle dbh, AddressSpace space,
			DBTraceSpaceEntry ent, TraceThread thread) throws VersionException, IOException {
		this.manager = manager;
		this.dbh = dbh;
		this.space = space;
		this.thread = thread;
		this.frameLevel = ent.getFrameLevel();
		this.lock = manager.getLock();
		this.baseLanguage = manager.getBaseLanguage();
		this.trace = manager.getTrace();
		this.dataTypeManager = manager.dataTypeManager;
		this.referenceManager = manager.referenceManager;
		this.all = new AddressRangeImpl(space.getMinAddress(), space.getMaxAddress());

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		long threadKey = ent.getThreadKey();
		int frameLevel = ent.getFrameLevel();

		instructionMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceInstruction.tableName(space, threadKey), factory, lock, space, null, 0,
			DBTraceInstruction.class, (t, s, r) -> new DBTraceInstruction(this, t, s, r));
		dataMapSpace = new DBTraceAddressSnapRangePropertyMapSpace<>(
			DBTraceData.tableName(space, threadKey, frameLevel), factory, lock, space, null, 0,
			DBTraceData.class, (t, s, r) -> new DBTraceData(this, t, s, r));

		instructions = createInstructionsView();
		definedData = createDefinedDataView();
		definedUnits = createDefinedUnitsView(); // depends on instructions,definedData
		undefinedData = createUndefinedDataView(); // dep: definedUnits
		data = createDataView(); // dep: definedData,undefinedData
		codeUnits = createCodeUnitsView(); // dep: instructions,definedData,undefinedData
	}

	/**
	 * A factory method for the instructions view
	 */
	protected DBTraceInstructionsView createInstructionsView() {
		return new DBTraceInstructionsView(this);
	}

	/**
	 * A factory method for the defined data view
	 */
	protected DBTraceDefinedDataView createDefinedDataView() {
		return new DBTraceDefinedDataView(this);
	}

	/**
	 * A factory method for the defined units view
	 */
	protected DBTraceDefinedUnitsView createDefinedUnitsView() {
		return new DBTraceDefinedUnitsView(this);
	}

	/**
	 * A factory method for the undefined data view
	 */
	protected DBTraceUndefinedDataView createUndefinedDataView() {
		return new DBTraceUndefinedDataView(this);
	}

	/**
	 * A factory method for the data view
	 */
	protected DBTraceDataView createDataView() {
		return new DBTraceDataView(this);
	}

	/**
	 * A factory method for the code units view
	 */
	protected DBTraceCodeUnitsView createCodeUnitsView() {
		return new DBTraceCodeUnitsView(this);
	}

	/**
	 * Clear all units belonging to the given guest platform
	 * 
	 * @param span the lifespan
	 * @param range the address range
	 * @param guest the guest platform
	 * @param monitor a monitor for progress
	 * @throws CancelledException if the monitor was cancelled
	 */
	void clearPlatform(Lifespan span, AddressRange range, DBTraceGuestPlatform guest,
			TaskMonitor monitor) throws CancelledException {
		// Note "makeWay" does not apply here.
		// Units should be enclosed by guest mapping.
		// TODO: Use sub-monitors when available
		monitor.setMessage("Clearing instructions");
		monitor.setMaximum(instructionMapSpace.size()); // This is OK

		instructions.invalidateCache();
		definedData.invalidateCache();
		undefinedData.invalidateCache();

		for (DBTraceInstruction instruction : instructionMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (instruction.platform != guest) {
				continue;
			}
			instructionMapSpace.deleteData(instruction);
			instructions.unitRemoved(instruction);
		}
		monitor.setMessage("Clearing data");
		monitor.setMaximum(dataMapSpace.size()); // This is OK
		for (DBTraceData dataUnit : dataMapSpace.reduce(
			TraceAddressSnapRangeQuery.intersecting(range, span)).values()) {
			monitor.checkCancelled();
			monitor.incrementProgress(1);
			if (dataUnit.platform != guest) {
				continue;
			}
			// TODO: I don't yet have guest-language data units.
			dataMapSpace.deleteData(dataUnit);
			definedData.unitRemoved(dataUnit);
		}
	}

	@Override
	public AddressSpace getAddressSpace() {
		return space;
	}

	@Override
	public TraceThread getThread() {
		return thread;
	}

	@Override
	public int getFrameLevel() {
		return frameLevel;
	}

	@Override
	public DBTraceCodeUnitsView codeUnits() {
		return codeUnits;
	}

	@Override
	public DBTraceInstructionsView instructions() {
		return instructions;
	}

	@Override
	public DBTraceDataView data() {
		return data;
	}

	@Override
	public DBTraceDefinedDataView definedData() {
		return definedData;
	}

	@Override
	public DBTraceUndefinedDataView undefinedData() {
		return undefinedData;
	}

	@Override
	public DBTraceDefinedUnitsView definedUnits() {
		return definedUnits;
	}

	@Override
	public void invalidateCache() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			instructionMapSpace.invalidateCache();
			instructions.invalidateCache();

			dataMapSpace.invalidateCache();
			definedData.invalidateCache();

			undefinedData.invalidateCache();
		}
	}

	/**
	 * Notify this space that some bytes have changed
	 * 
	 * <p>
	 * If any unit(s) contained the changed bytes, they may need to be truncated, deleted, and/or
	 * replaced. Instructions are generally truncated or deleted without replacement. A data unit
	 * may be replaced if its length would match that of the original.
	 * 
	 * @param changed the boxes whose bytes changed
	 * @param snap the snap where the client requested the change
	 * @param start the starting address where the client requested the change
	 * @param oldBytes the old bytes
	 * @param newBytes the new bytes
	 */
	public void bytesChanged(Set<TraceAddressSnapRange> changed, long snap, Address start,
			byte[] oldBytes, byte[] newBytes) {
		AddressSet diffs = ByteArrayUtils.computeDiffsAddressSet(start, oldBytes, newBytes);
		Set<AbstractDBTraceCodeUnit<?>> affectedUnits = new HashSet<>();
		for (TraceAddressSnapRange box : changed) {
			if (!diffs.intersects(box.getX1(), box.getX2())) {
				continue;
			}
			for (AbstractDBTraceCodeUnit<?> unit : definedUnits.getIntersecting(box)) {
				if (diffs.intersects(unit.getMinAddress(), unit.getMaxAddress())) {
					affectedUnits.add(unit);
				}
			}
		}

		MemBuffer newBuf =
			new ByteMemBufferImpl(start, newBytes, trace.getBaseLanguage().isBigEndian());
		for (AbstractDBTraceCodeUnit<?> unit : affectedUnits) {
			// Rule:
			//     Break unit down into time portions before affected range, and at/within range
			//     For Data in affected range:
			//         For dynamic types, only accept if the length is unaffected
			//         For simple types, just re-apply
			//     For Instruction in affected range:
			//         Probably just delete it.
			long unitStartSnap;
			long unitEndSnap = unit.getEndSnap();
			if (unit.getStartSnap() < snap) {
				unit.setEndSnap(snap - 1);
				unitStartSnap = snap;
			}
			else {
				unitStartSnap = unit.getStartSnap();
				unit.delete();
			}
			if (unit instanceof DBTraceData) {
				DBTraceData dataUnit = (DBTraceData) unit;
				boolean reApply = false;
				DataType dataType = dataUnit.getDataType();
				if (dataType instanceof Dynamic) {
					Dynamic ddt = (Dynamic) dataType;
					WrappedMemBuffer newWrapped =
						new WrappedMemBuffer(newBuf, (int) dataUnit.getAddress().subtract(start));
					int newLength = ddt.getLength(newWrapped, dataUnit.getLength());
					reApply = newLength == unit.getLength();
				}
				else {
					reApply = true;
				}
				if (reApply) {
					try {
						definedData.create(Lifespan.span(unitStartSnap, unitEndSnap),
							unit.getAddress(), dataType, unit.getLength());
					}
					catch (CodeUnitInsertionException e) {
						throw new AssertionError(e);
					}
				}
			}
		}
	}
}
