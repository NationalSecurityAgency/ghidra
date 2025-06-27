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

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.trace.database.guest.InternalTracePlatform;
import ghidra.trace.database.memory.DBTraceMemorySpace;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.listing.TraceCodeSpace;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;

/**
 * The implementation of {@link TraceCodeSpace#definedData()}
 */
public class DBTraceDefinedDataView extends AbstractBaseDBTraceDefinedUnitsView<DBTraceData>
		implements InternalTraceDefinedDataView {
	/**
	 * Construct the view
	 * 
	 * @param space the space, bound to an address space
	 */
	public DBTraceDefinedDataView(DBTraceCodeSpace space) {
		super(space, space.dataMapSpace);
	}

	@Override // NOTE: "Adapter" because using DataType.DEFAULT gives UndefinedDBTraceData
	public DBTraceDataAdapter create(Lifespan lifespan, Address address, TracePlatform platform,
			DataType dataType) throws CodeUnitInsertionException {
		return create(lifespan, address, platform, dataType, dataType.getLength());
	}

	/**
	 * Check if the given data type represents a function definition
	 * 
	 * <p>
	 * This recursively resolves typedefs and checks each.
	 * 
	 * @param dt the data type
	 * @return true if it is a function definition, false otherwise
	 */
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
	public DBTraceDataAdapter create(Lifespan lifespan, Address address, TracePlatform platform,
			DataType origType, int origLength) throws CodeUnitInsertionException {
		if (platform.getTrace() != getTrace() ||
			!(platform instanceof InternalTracePlatform iPlatform)) {
			throw new IllegalArgumentException("Platform is not part of this trace");
		}
		try (LockHold hold = LockHold.lock(space.lock.writeLock())) {
			DBTraceMemorySpace memSpace = space.trace.getMemoryManager().get(space.space, true);
			// NOTE: User-given length could be ignored....
			// Check start address first. After I know length, I can check for other existing units
			long startSnap = lifespan.lmin();
			if (!space.undefinedData.coversRange(Lifespan.at(startSnap),
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
			DataTypeManager dtm = platform.getDataTypeManager();
			dataType = dataType.clone(dtm);

			if (isFunctionDefinition(dataType)) {
				dataType = new PointerDataType(dataType, dtm);
				length = dataType.getLength();
			}
			else if (dataType instanceof Dynamic) {
				// TODO: Should I consider no observations to be "uninitialized"?
				// If so, dynamic types cannot be applied here
				Dynamic dyn = (Dynamic) dataType;
				MemBuffer buffer = memSpace.getBufferAt(startSnap, address);
				length = dyn.getLength(buffer, length);
			}
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

			// Truncate, then check that against existing code units.
			long endSnap = computeTruncatedMax(lifespan, null, createdRange);
			TraceAddressSnapRange tasr = new ImmutableTraceAddressSnapRange(createdRange,
				Lifespan.span(startSnap, endSnap));
			if (!space.undefinedData.coversRange(tasr)) {
				// TODO: Figure out the conflicting unit?
				throw new CodeUnitInsertionException("Code units cannot overlap");
			}

			if (dataType == DataType.DEFAULT) {
				return space.undefinedData.getAt(startSnap, address);
			}

			long dataTypeID = dtm.getResolvedID(dataType);
			DBTraceData created = mapSpace.put(tasr, null);
			created.set(iPlatform, dataTypeID);
			// TODO: Explicitly remove undefined from cache, or let weak refs take care of it?

			cacheForContaining.notifyNewEntry(tasr.getLifespan(), createdRange, created);
			cacheForSequence.notifyNewEntry(tasr.getLifespan(), createdRange, created);
			space.undefinedData.invalidateCache();

			if (dataType instanceof Composite || dataType instanceof Array ||
				dataType instanceof Dynamic) {
				// TODO: Track composites?
				space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.COMPOSITE_DATA_ADDED,
					space.space, tasr, created));
			}

			space.trace.setChanged(
				new TraceChangeRecord<>(TraceEvents.CODE_ADDED, space.space, tasr, created));
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
			space.trace.setChanged(new TraceChangeRecord<>(TraceEvents.COMPOSITE_DATA_REMOVED,
				space.space, unit.getBounds(), unit, null));
		}
	}

	@Override
	protected void unitSpanChanged(Lifespan oldSpan, DBTraceData unit) {
		super.unitSpanChanged(oldSpan, unit);
		DataType dataType = unit.getBaseDataType();
		if (dataType instanceof Composite || dataType instanceof Array ||
			dataType instanceof Dynamic) {
			space.trace.setChanged(
				new TraceChangeRecord<>(TraceEvents.COMPOSITE_DATA_LIFESPAN_CHANGED,
					space.space, unit, oldSpan, unit.getLifespan()));
		}
	}
}
