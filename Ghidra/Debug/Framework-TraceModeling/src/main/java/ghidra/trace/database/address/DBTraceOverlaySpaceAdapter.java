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
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
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
			extends AbstractDBFieldCodec<Address, OT, BinaryField> {
		static final Charset UTF8 = Charset.forName("UTF-8");

		public AddressDBFieldCodec(Class<OT> objectType, Field field, int column) {
			super(Address.class, objectType, BinaryField.class, field, column);
		}

		protected byte[] encode(Address address) {
			if (address == null) {
				return null;
			}
			AddressSpace as = address.getAddressSpace();
			ByteBuffer buf = ByteBuffer.allocate(Byte.BYTES + Short.BYTES + Long.BYTES);
			if (as instanceof OverlayAddressSpace) {
				buf.put((byte) 1);
				OverlayAddressSpace os = (OverlayAddressSpace) as;
				buf.putShort((short) os.getDatabaseKey());
			}
			else {
				buf.put((byte) 0);
				buf.putShort((short) as.getSpaceID());
			}
			buf.putLong(address.getOffset());
			return buf.array();
		}

		@Override
		public void store(Address value, BinaryField f) {
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
			if (data == null) {
				setValue(obj, null);
			}
			else {
				ByteBuffer buf = ByteBuffer.wrap(data);
				byte overlay = buf.get();
				final AddressSpace as;
				if (overlay == 1) {
					short key = buf.getShort();
					as = obj.getOverlaySpaceAdapter().spacesByKey.get(key & 0xffffL);
				}
				else {
					short id = buf.getShort();
					as = obj.getOverlaySpaceAdapter().trace.getInternalAddressFactory()
							.getAddressSpace(id);
				}
				long offset = buf.getLong();
				setValue(obj, as.getAddress(offset));
			}
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class DBTraceOverlaySpaceEntry extends DBAnnotatedObject {

		static final String TABLE_NAME = "AddressSpaces";

		static final String NAME_COLUMN_NAME = "Name";
		static final String BASE_COLUMN_NAME = "Base";

		// NOTE: I don't care to record min/max limit

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

	private final Map<Long, AddressSpace> spacesByKey = new HashMap<>();

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
		// Clean and rename existing overlays, first
		for (AddressSpace space : factory.getAllAddressSpaces()) {
			if (!(space instanceof OverlayAddressSpace)) {
				continue;
			}
			OverlayAddressSpace os = (OverlayAddressSpace) space;
			DBTraceOverlaySpaceEntry ent = overlayStore.getObjectAt(os.getDatabaseKey());
			if (ent == null) {
				spacesByKey.remove(os.getDatabaseKey());
				factory.removeOverlaySpace(os.getName());
			}
			else if (!os.getName().equals(ent.name)) {
				factory.removeOverlaySpace(os.getName());
				os.setName(ent.name);
				try {
					factory.addOverlayAddressSpace(os);
				}
				catch (DuplicateNameException e) {
					throw new AssertionError(); // I just removed it
				}
			}
			// else it's already in sync
		}
		// Add missing overlays
		for (DBTraceOverlaySpaceEntry ent : overlayStore.asMap().values()) {
			AddressSpace exists = factory.getAddressSpace(ent.name);
			if (exists != null) {
				// it's already in sync and/or its a physical space
				continue;
			}
			AddressSpace baseSpace = factory.getAddressSpace(ent.baseSpace);
			try {
				OverlayAddressSpace space = factory.addOverlayAddressSpace(ent.name, true,
					baseSpace, baseSpace.getMinAddress().getOffset(),
					baseSpace.getMaxAddress().getOffset());
				space.setDatabaseKey(ent.getKey());
				spacesByKey.put(space.getDatabaseKey(), space);
			}
			catch (IllegalArgumentException e) {
				throw new AssertionError(); // Name should be validated already, no?
			}
		}
	}

	public AddressSpace createOverlayAddressSpace(String name, AddressSpace base)
			throws DuplicateNameException {
		// TODO: Exclusive lock?
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			TraceAddressFactory factory = trace.getInternalAddressFactory();
			if (factory.getAddressSpace(name) != null) {
				throw new DuplicateNameException("Address space " + name + " already exists.");
			}

			OverlayAddressSpace space =
				factory.addOverlayAddressSpace(name, true, base, base.getMinAddress().getOffset(),
					base.getMaxAddress().getOffset());
			// Only if it succeeds do we store the record
			DBTraceOverlaySpaceEntry ent = overlayStore.create();
			ent.set(space.getName(), base.getName());
			return space;
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
			factory.removeOverlaySpace(name);
		}
	}
}
