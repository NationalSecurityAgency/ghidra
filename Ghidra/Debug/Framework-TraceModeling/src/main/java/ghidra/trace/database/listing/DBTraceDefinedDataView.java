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

import com.google.common.collect.Range;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace.TraceCodeChangeType;
import ghidra.trace.model.Trace.TraceCompositeDataChangeType;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.trace.model.listing.TraceDefinedDataView;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;

public class DBTraceDefinedDataView extends AbstractBaseDBTraceDefinedUnitsView<DBTraceData>
		implements TraceDefinedDataView {
	public DBTraceDefinedDataView(DBTraceCodeSpace space) {
		super(space, space.dataMapSpace);
	}

	@Override // NOTE: "Adapter" because using DataType.DEFAULT gives UndefinedDBTraceData
	public DBTraceDataAdapter create(Range<Long> lifespan, Address address, DataType dataType)
			throws CodeUnitInsertionException {
		return create(lifespan, address, dataType, dataType.getLength());
	}

	protected boolean isFunctionDefinition(DataType dt) {
		if (dt instanceof FunctionDefinition) {
			return true;
		}
		if (dt instanceof TypeDef) {
			TypeDef typeDef = (TypeDef) dt;
			return isFunctionDefinition(typeDef.getBaseDataType());
		}
		return false;
	}

	@Override
	// TODO: Probably add language parameter....
	public DBTraceDataAdapter create(Range<Long> lifespan, Address address, DataType origType,
			int origLength) throws CodeUnitInsertionException {
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			DBTraceMemorySpace memSpace = space.trace.getMemoryManager().get(space, true);
			// NOTE: User-given length could be ignored....
			// Check start address first. After I know length, I can check for other existing units
			long startSnap = DBTraceUtils.lowerEndpoint(lifespan);
			if (!space.undefinedData.coversRange(Range.closed(startSnap, startSnap),
				new AddressRangeImpl(address, address))) {
				// TODO: Figure out the conflicting unit?
				throw new CodeUnitInsertionException("Code units cannot overlap");
			}

			DataType dataType;
			int length;
			if (origType instanceof FactoryDataType) {
				MemBuffer buffer = memSpace.getBufferAt(startSnap, address);
				FactoryDataType fdt = (FactoryDataType) origType;
				dataType = fdt.getDataType(buffer);
				length = -1;
			}
			else {
				dataType = origType;
				length = origLength;
			}

			if (dataType == null) {
				throw new CodeUnitInsertionException("Failed to resolve data type");
			}
			// TODO: This clone may need to be sensitive to the unit's language.
			dataType = dataType.clone(space.dataTypeManager);

			if (isFunctionDefinition(dataType)) {
				// TODO: This pointer will need to be sensitive to the unit's language.
				dataType = new PointerDataType(dataType, dataType.getDataTypeManager());
				length = dataType.getLength();
			}
			else if (dataType instanceof Dynamic) {
				// TODO: Should I consider no observations to be "uninitialized"?
				// If so, dynamic types cannot be applied here
				Dynamic dyn = (Dynamic) dataType;
				MemBuffer buffer = memSpace.getBufferAt(startSnap, address);
				length = dyn.getLength(buffer, length);
			}
			// TODO: Do I need to check for Pointer type here?
			// Seems purpose is to adjust for language, but I think clone does that already
			else {
				length = dataType.getLength();
			}

			if (length < 0) {
				throw new CodeUnitInsertionException(
					"Failed to resolve data length for " + origType.getName());
			}
			if (length == 0) {
				throw new CodeUnitInsertionException(
					"Zero-length data not allowed " + origType.getName());
			}

			Address endAddress = address.addNoWrap(length - 1);
			AddressRangeImpl createdRange = new AddressRangeImpl(address, endAddress);

			// First, truncate lifespan to the next unit in the range, if end is unbounded
			if (!lifespan.hasUpperBound()) {
				lifespan = space.instructions.truncateSoonestDefined(lifespan, createdRange);
				lifespan = space.definedData.truncateSoonestDefined(lifespan, createdRange);
			}

			// Second, extend to the next change of bytes in the range within lifespan
			// Then, check that against existing code units.
			long endSnap = memSpace.getFirstChange(lifespan, createdRange);
			if (endSnap == Long.MIN_VALUE) {
				endSnap = DBTraceUtils.upperEndpoint(lifespan);
			}
			else {
				endSnap--;
			}
			TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(createdRange,
				DBTraceUtils.toRange(startSnap, endSnap));
			if (!space.undefinedData.coversRange(tasr)) {
				// TODO: Figure out the conflicting unit?
				throw new CodeUnitInsertionException("Code units cannot overlap");
			}

			if (dataType == DataType.DEFAULT) {
				return space.undefinedData.getAt(startSnap, address);
			}

			DBTraceData created = space.dataMapSpace.put(tasr, null);
			created.set(space.baseLanguage, dataType);
			// TODO: Explicitly remove undefined from cache, or let weak refs take care of it?

			cacheForContaining.notifyNewEntry(lifespan, createdRange, created);
			cacheForSequence.notifyNewEntry(lifespan, createdRange, created);
			space.undefinedData.invalidateCache();

			if (dataType instanceof Composite || dataType instanceof Array ||
				dataType instanceof Dynamic) {
				// TODO: Track composites?
				space.trace.setChanged(new TraceChangeRecord<>(TraceCompositeDataChangeType.ADDED,
					space, tasr, created));
			}

			space.trace.setChanged(new TraceChangeRecord<>(TraceCodeChangeType.ADDED,
				space, tasr, created));
			return created;
		}
		catch (AddressOverflowException e) {
			throw new CodeUnitInsertionException("Could unit would extend beyond address space");
		}
	}

	@Override
	protected void unitRemoved(DBTraceData unit) {
		super.unitRemoved(unit);
		DataType dataType = unit.getBaseDataType();
		if (dataType instanceof Composite || dataType instanceof Array ||
			dataType instanceof Dynamic) {
			space.trace.setChanged(new TraceChangeRecord<>(TraceCompositeDataChangeType.REMOVED,
				space, unit.getBounds(), unit, null));
		}
	}

	@Override
	protected void unitSpanChanged(Range<Long> oldSpan, DBTraceData unit) {
		super.unitSpanChanged(oldSpan, unit);
		DataType dataType = unit.getBaseDataType();
		if (dataType instanceof Composite || dataType instanceof Array ||
			dataType instanceof Dynamic) {
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceCompositeDataChangeType.LIFESPAN_CHANGED,
					space, unit, oldSpan, unit.getLifespan()));
		}
	}
}
