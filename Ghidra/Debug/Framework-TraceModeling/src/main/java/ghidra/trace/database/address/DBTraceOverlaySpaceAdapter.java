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
package ghidra.trace.database.address;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import db.*;
import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.database.ProgramOverlayAddressSpace;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.model.Trace.TraceOverlaySpaceChangeType;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceOverlaySpaceAdapter implements DBTraceManager {

	/**
	 * An interface required for any object having a field using {@link AddressDBFieldCodec}.
	 */
	public interface DecodesAddresses {
		/**
		 * Get the space adapter for the trace containing the object
		 * 
		 * @return the adapter
		 */
		DBTraceOverlaySpaceAdapter getOverlaySpaceAdapter();
	}

	/**
	 * Used for objects having an {@link Address} field.
	 * 
	 * <p>
	 * Most managers storing things by address will actually have a table per space, so the address
	 * is encoded only as an offset. However, any other {@link Address} field (not constrained to
	 * the same space) will need to encode the space information as well. This codec can do that.
	 * The object will need to return its trace's space adapter, though.
	 * 
	 * @param <OT> the type of object containing the field
	 */
	public static class AddressDBFieldCodec<OT extends DBAnnotatedObject & DecodesAddresses>
			extends AbstractDBFieldCodec<Address, OT, FixedField10> {
		static final Charset UTF8 = Charset.forName("UTF-8");

		public static byte[] encode(Address address) {
			if (address == null) {
				return null;
			}
			AddressSpace as = address.getAddressSpace();
			ByteBuffer buf = ByteBuffer.allocate(Short.BYTES + Long.BYTES);
			buf.putShort((short) as.getSpaceID());
			buf.putLong(address.getOffset());
			return buf.array();
		}

		public static Address decode(byte[] enc, DBTraceOverlaySpaceAdapter osa) {
			if (enc == null) {
				return null;
			}
			ByteBuffer buf = ByteBuffer.wrap(enc);
			short id = buf.getShort();
			final AddressSpace as = osa.trace.getInternalAddressFactory().getAddressSpace(id);
			long offset = buf.getLong();
			return as.getAddress(offset);
		}

		public AddressDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(Address.class, objectType, FixedField10.class, field, column);
		}

		@Override
		public void store(Address value, FixedField10 f) {
			f.setBinaryData(encode(value));
		}

		@Override
		protected void doStore(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setBinaryData(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(OT obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			byte[] data = record.getBinaryData(column);
			setValue(obj, decode(data, obj.getOverlaySpaceAdapter()));
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceOverlaySpaceEntry extends DBAnnotatedObject {

		static final String TABLE_NAME = "AddressSpaces";

		static final String NAME_COLUMN_NAME = "Name";
		static final String BASE_COLUMN_NAME = "Base";

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;
		@DBAnnotatedColumn(BASE_COLUMN_NAME)
		static DBObjectColumn BASE_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
		String name;
		@DBAnnotatedField(column = BASE_COLUMN_NAME)
		String baseSpace;

		public DBTraceOverlaySpaceEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		void set(String name, String baseSpace) {
			this.name = name;
			this.baseSpace = baseSpace;
			update(NAME_COLUMN, BASE_COLUMN);
		}
	}

	protected final DBHandle dbh;
	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceOverlaySpaceEntry> overlayStore;
	protected final DBCachedObjectIndex<String, DBTraceOverlaySpaceEntry> overlaysByName;

	public DBTraceOverlaySpaceAdapter(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, DBTrace trace) throws VersionException, IOException {
		this.dbh = dbh;
		this.lock = lock;
		this.trace = trace;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		overlayStore = factory.getOrCreateCachedStore(DBTraceOverlaySpaceEntry.TABLE_NAME,
			DBTraceOverlaySpaceEntry.class, DBTraceOverlaySpaceEntry::new, true);
		overlaysByName = overlayStore.getIndex(String.class, DBTraceOverlaySpaceEntry.NAME_COLUMN);
		resyncAddressFactory();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			overlayStore.invalidateCache();
			resyncAddressFactory();
		}
	}

	protected void resyncAddressFactory() {
		TraceAddressFactory factory = trace.getInternalAddressFactory();
		resyncAddressFactory(factory);
	}

	protected void resyncAddressFactory(TraceAddressFactory factory) {

		// Perform reconciliation of overlay address spaces while attempting to preserve 
		// address space instances associated with a given key

		// Put all overlay records into key-based map
		Map<Long, DBTraceOverlaySpaceEntry> keyToRecordMap = new HashMap<>(overlayStore.asMap());

		// Examine existing overlay spaces for removals and renames
		List<ProgramOverlayAddressSpace> renameList = new ArrayList<>();
		for (AddressSpace space : factory.getAllAddressSpaces()) {
			if (space instanceof ProgramOverlayAddressSpace os) {
				String name = os.getName();
				DBTraceOverlaySpaceEntry ent = keyToRecordMap.get(os.getKey());
				if (ent == null || !isCompatibleOverlay(os, ent, factory)) {
					// Remove overlay if entry does not exist or base space differs
					factory.removeOverlaySpace(name);
				}
				else if (name.equals(ent.name)) {
					keyToRecordMap.remove(os.getKey());
					continue; // no change to space
				}
				else {
					// Add space to map of those that need to be renamed
					renameList.add(os);
					factory.removeOverlaySpace(name);
				}
			}
		}

		try {
			// Handle all renamed overlays which had been temporarily removed from factory
			for (ProgramOverlayAddressSpace existingSpace : renameList) {
				long key = existingSpace.getKey();
				DBTraceOverlaySpaceEntry ent = keyToRecordMap.get(key);
				existingSpace.setName(ent.name);
				factory.addOverlaySpace(existingSpace); // re-add renamed space
				keyToRecordMap.remove(key);
			}

			// Add any remaing overlay which are missing from factory
			for (long key : keyToRecordMap.keySet()) {
				DBTraceOverlaySpaceEntry ent = keyToRecordMap.get(key);
				String spaceName = ent.name;
				AddressSpace baseSpace = factory.getAddressSpace(ent.baseSpace);
				factory.addOverlaySpace(key, spaceName, baseSpace);
			}
		}
		catch (IllegalArgumentException | DuplicateNameException e) {
			throw new AssertionError("Unexpected error updating overlay address spaces", e);
		}

		factory.refreshStaleOverlayStatus();
	}

	private boolean isCompatibleOverlay(ProgramOverlayAddressSpace os, DBTraceOverlaySpaceEntry ent,
			ProgramAddressFactory factory) {
		AddressSpace baseSpace = factory.getAddressSpace(ent.baseSpace);
		if (baseSpace == null) {
			// Error condition should be handled better - language may have dropped original base space
			throw new RuntimeException("Base space for overlay not found: " + ent.baseSpace);
		}
		return baseSpace == os.getOverlayedSpace();
	}

	protected AddressSpace doCreateOverlaySpace(String name, AddressSpace base)
			throws DuplicateNameException {
		TraceAddressFactory factory = trace.getInternalAddressFactory();

		if (!factory.isValidOverlayBaseSpace(base)) {
			throw new IllegalArgumentException(
				"Invalid address space for overlay: " + base.getName());
		}

		if (factory.getAddressSpace(name) != null) {
			throw new DuplicateNameException(
				"Overlay space '" + name + "' duplicates name of another address space");
		}

		DBTraceOverlaySpaceEntry ent = overlayStore.create();
		ProgramOverlayAddressSpace space = factory.addOverlaySpace(ent.getKey(), name, base);

		// Only if it succeeds do we store the record
		ent.set(space.getName(), base.getName());
		trace.updateViewsAddSpaceBlock(space);
		trace.setChanged(
			new TraceChangeRecord<>(TraceOverlaySpaceChangeType.ADDED, null, trace, null, space));
		return space;
	}

	public AddressSpace createOverlayAddressSpace(String name, AddressSpace base)
			throws DuplicateNameException {
		// TODO: Exclusive lock?
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			TraceAddressFactory factory = trace.getInternalAddressFactory();
			if (factory.getAddressSpace(name) != null) {
				throw new DuplicateNameException("Address space " + name + " already exists.");
			}
			return doCreateOverlaySpace(name, base);
		}
	}

	public AddressSpace getOrCreateOverlayAddressSpace(String name, AddressSpace base) {
		// TODO: Exclusive lock?
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			TraceAddressFactory factory = trace.getInternalAddressFactory();
			AddressSpace space = factory.getAddressSpace(name);
			if (space != null) {
				return space.getPhysicalSpace() == base ? space : null;
			}
			try {
				return doCreateOverlaySpace(name, base);
			}
			catch (DuplicateNameException e) {
				throw new AssertionError(e);
			}
		}
	}

	public void deleteOverlayAddressSpace(String name) {
		// TODO: Exclusive lock?
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			DBTraceOverlaySpaceEntry exists = overlaysByName.getOne(name);
			if (exists == null) {
				throw new NoSuchElementException(name);
			}
			overlayStore.delete(exists);
			TraceAddressFactory factory = trace.getInternalAddressFactory();
			AddressSpace space = factory.getAddressSpace(name);
			assert space != null;
			factory.removeOverlaySpace(name);
			trace.updateViewsDeleteSpaceBlock(space);
			trace.setChanged(new TraceChangeRecord<>(TraceOverlaySpaceChangeType.DELETED, null,
				trace, space, null));
			invalidateCache(true);
		}
	}

}
