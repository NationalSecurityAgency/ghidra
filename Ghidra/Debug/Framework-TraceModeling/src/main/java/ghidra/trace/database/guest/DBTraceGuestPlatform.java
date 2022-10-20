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
package ghidra.trace.database.guest;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.Pair;

import db.DBRecord;
import ghidra.app.util.PseudoInstruction;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.DBTraceUtils.CompilerSpecIDDBFieldCodec;
import ghidra.trace.database.DBTraceUtils.LanguageIDDBFieldCodec;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TracePlatformChangeType;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TraceGuestPlatformMappedRange;
import ghidra.trace.util.OverlappingObjectIterator;
import ghidra.trace.util.OverlappingObjectIterator.Ranger;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceGuestPlatform extends DBAnnotatedObject
		implements TraceGuestPlatform, InternalTracePlatform {
	public static final String TABLE_NAME = "Platforms";

	private static enum MappedRangeRanger implements Ranger<DBTraceGuestPlatformMappedRange> {
		HOST {
			@Override
			AddressRange getRange(DBTraceGuestPlatformMappedRange t) {
				return t.getHostRange();
			}
		},
		GUEST {
			@Override
			AddressRange getRange(DBTraceGuestPlatformMappedRange t) {
				return t.getGuestRange();
			}
		};

		abstract AddressRange getRange(DBTraceGuestPlatformMappedRange t);

		@Override
		public Address getMinAddress(DBTraceGuestPlatformMappedRange t) {
			return getRange(t).getMinAddress();
		}

		@Override
		public Address getMaxAddress(DBTraceGuestPlatformMappedRange t) {
			return getRange(t).getMaxAddress();
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceGuestLanguage extends DBAnnotatedObject {
		public static final String TABLE_NAME = "Languages";

		static final String LANGID_COLUMN_NAME = "Lang";
		static final String VERSION_COLUMN_NAME = "Version";
		static final String MINOR_VERSION_COLUMN_NAME = "MinorVersion";

		@DBAnnotatedColumn(LANGID_COLUMN_NAME)
		static DBObjectColumn LANGID_COLUMN;
		@DBAnnotatedColumn(VERSION_COLUMN_NAME)
		static DBObjectColumn VERSION_COLUMN;
		@DBAnnotatedColumn(MINOR_VERSION_COLUMN_NAME)
		static DBObjectColumn MINOR_VERSION_COLUMN;

		@DBAnnotatedField(column = LANGID_COLUMN_NAME, codec = LanguageIDDBFieldCodec.class)
		private LanguageID langID;
		@DBAnnotatedField(column = VERSION_COLUMN_NAME)
		private int version;
		@DBAnnotatedField(column = MINOR_VERSION_COLUMN_NAME)
		private int minorVersion;

		private Language language;

		public DBTraceGuestLanguage(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		@Override
		protected void fresh(boolean created) throws IOException {
			super.fresh(created);
			if (created) {
				return;
			}
			LanguageService langServ = DefaultLanguageService.getLanguageService();
			language = langServ.getLanguage(langID);
			if (version != language.getVersion() || minorVersion != language.getMinorVersion()) {
				throw new IOException(new VersionException()); // TODO Upgrade
			}
		}

		void set(Language language) {
			this.langID = language.getLanguageID();
			this.version = language.getVersion();
			this.minorVersion = language.getMinorVersion();
			update(LANGID_COLUMN, VERSION_COLUMN, MINOR_VERSION_COLUMN);
			this.language = language;
		}

		public Language getLanguage() {
			return language;
		}
	}

	static final String LANGKEY_COLUMN_NAME = "Lang";
	static final String CSPECID_COLUMN_NAME = "CSpec";

	@DBAnnotatedColumn(LANGKEY_COLUMN_NAME)
	static DBObjectColumn LANGKEY_COLUMN;
	@DBAnnotatedColumn(CSPECID_COLUMN_NAME)
	static DBObjectColumn CSPECID_COLUMN;

	@DBAnnotatedField(column = LANGKEY_COLUMN_NAME)
	private int langKey;
	@DBAnnotatedField(column = CSPECID_COLUMN_NAME, codec = CompilerSpecIDDBFieldCodec.class)
	private CompilerSpecID cSpecID;

	private DBTraceGuestLanguage languageEntry;
	private CompilerSpec compilerSpec;

	final DBTracePlatformManager manager;
	protected final NavigableMap<Address, DBTraceGuestPlatformMappedRange> rangesByHostAddress =
		new TreeMap<>();
	protected final AddressSet hostAddressSet = new AddressSet();

	protected final NavigableMap<Address, DBTraceGuestPlatformMappedRange> rangesByGuestAddress =
		new TreeMap<>();
	protected final AddressSet guestAddressSet = new AddressSet();

	public DBTraceGuestPlatform(DBTracePlatformManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	void set(CompilerSpec compilerSpec) {
		this.languageEntry = manager.getOrCreateLanguage(compilerSpec.getLanguage());
		this.langKey = (int) (languageEntry == null ? -1 : languageEntry.getKey());
		this.cSpecID = compilerSpec.getCompilerSpecID();
		update(LANGKEY_COLUMN, CSPECID_COLUMN);
		this.compilerSpec = compilerSpec;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		super.fresh(created);
		if (created) {
			return;
		}
		this.languageEntry = manager.getLanguageByKey(langKey);
		if (languageEntry == null && langKey != -1) {
			throw new IOException("Platform table is corrupt. Missing language " + langKey);
		}
		compilerSpec = getLanguage().getCompilerSpecByID(cSpecID);
		if (compilerSpec == null) {
			throw new IOException(
				"Platform table is corrupt. Invalid compiler spec " + compilerSpec);
		}
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public int getIntKey() {
		return (int) key;
	}

	@Override
	public boolean isGuest() {
		return true;
	}

	protected void deleteMappedRange(DBTraceGuestPlatformMappedRange range, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			manager.trace.getCodeManager()
					.clearPlatform(Lifespan.ALL, range.getHostRange(), this, monitor);
			manager.rangeMappingStore.delete(range);
			AddressRange hostRange = range.getHostRange();
			AddressRange guestRange = range.getGuestRange();
			rangesByHostAddress.remove(hostRange.getMinAddress());
			rangesByGuestAddress.remove(guestRange.getMinAddress());
			hostAddressSet.delete(hostRange);
			guestAddressSet.delete(guestRange);
		}
		manager.trace.setChanged(new TraceChangeRecord<>(TracePlatformChangeType.MAPPING_DELETED,
			null, this, range, null));
	}

	@Override
	@Internal
	public DBTraceGuestLanguage getLanguageEntry() {
		return languageEntry;
	}

	@Override
	public Language getLanguage() {
		return languageEntry == null ? manager.baseLanguage : languageEntry.getLanguage();
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	@Override
	public void delete(TaskMonitor monitor) throws CancelledException {
		manager.deleteGuestPlatform(this, monitor);
		// TODO: Delete language once no platform uses it?
	}

	@Override
	public DBTraceGuestPlatformMappedRange addMappedRange(Address hostStart, Address guestStart,
			long length) throws AddressOverflowException {
		DBTraceGuestPlatformMappedRange mappedRange;
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			Address hostEnd = hostStart.addWrap(length - 1);
			if (hostAddressSet.intersects(hostStart, hostEnd)) {
				// TODO: Check for compatibility and extend?
				throw new IllegalArgumentException(
					"Range overlaps existing host mapped range(s) for this guest language");
			}
			Address guestEnd = guestStart.addWrap(length - 1);
			if (guestAddressSet.intersects(guestStart, guestEnd)) {
				throw new IllegalArgumentException("Range overlaps existing guest mapped range(s)");
			}
			mappedRange = manager.rangeMappingStore.create();
			mappedRange.set(hostStart, this, guestStart, length);
			rangesByHostAddress.put(hostStart, mappedRange);
			rangesByGuestAddress.put(guestStart, mappedRange);
			hostAddressSet.add(mappedRange.getHostRange());
			guestAddressSet.add(mappedRange.getGuestRange());
		}
		manager.trace.setChanged(new TraceChangeRecord<>(TracePlatformChangeType.MAPPING_ADDED,
			null, this, null, mappedRange));
		return mappedRange;
	}

	protected Address computeNextRegisterMin() {
		Address regMax = manager.hostPlatform.getLanguage()
				.getAddressFactory()
				.getRegisterSpace()
				.getMaxAddress();
		AddressRangeIterator rit = hostAddressSet.getAddressRanges(regMax, false);
		if (!rit.hasNext()) {
			return null;
		}
		AddressRange next = rit.next();
		if (!next.getAddressSpace().isRegisterSpace()) {
			return null;
		}
		return next.getMaxAddress().add(1);
	}

	@Override
	public TraceGuestPlatformMappedRange addMappedRegisterRange()
			throws AddressOverflowException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			AddressRange guestRange = getRegistersRange();
			if (guestRange == null) {
				return null; // No registers, so we're mapped!
			}
			Address hostMin = manager.computeNextRegisterMin();
			long size = guestRange.getLength();
			return addMappedRange(hostMin, guestRange.getMinAddress(), size);
		}
	}

	@Override
	public AddressSetView getHostAddressSet() {
		return new AddressSet(hostAddressSet);
	}

	@Override
	public AddressSetView getGuestAddressSet() {
		return new AddressSet(guestAddressSet);
	}

	@Override
	public Address mapHostToGuest(Address hostAddress) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestPlatformMappedRange> floorEntry =
				rangesByHostAddress.floorEntry(hostAddress);
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapHostToGuest(hostAddress);
		}
	}

	@Override
	public AddressRange mapHostToGuest(AddressRange hostRange) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestPlatformMappedRange> floorEntry =
				rangesByHostAddress.floorEntry(hostRange.getMinAddress());
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapHostToGuest(hostRange);
		}
	}

	@Override
	public AddressSetView mapHostToGuest(AddressSetView hostSet) {
		Iterator<Pair<DBTraceGuestPlatformMappedRange, AddressRange>> it =
			new OverlappingObjectIterator<DBTraceGuestPlatformMappedRange, AddressRange>(
				rangesByHostAddress.values().iterator(), MappedRangeRanger.HOST,
				hostSet.iterator(), OverlappingObjectIterator.ADDRESS_RANGE);
		AddressSet result = new AddressSet();
		while (it.hasNext()) {
			Pair<DBTraceGuestPlatformMappedRange, AddressRange> next = it.next();
			DBTraceGuestPlatformMappedRange entry = next.getLeft();
			AddressRange hostRange = next.getRight();
			result.add(entry.mapHostToGuest(hostRange));
		}
		return result;
	}

	@Override
	public Address mapGuestToHost(Address guestAddress) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestPlatformMappedRange> floorEntry =
				rangesByGuestAddress.floorEntry(guestAddress);
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapGuestToHost(guestAddress);
		}
	}

	@Override
	public AddressRange mapGuestToHost(AddressRange guestRange) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestPlatformMappedRange> floorEntry =
				rangesByGuestAddress.floorEntry(guestRange.getMinAddress());
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapGuestToHost(guestRange);
		}
	}

	@Override
	public AddressSetView mapGuestToHost(AddressSetView guestSet) {
		Iterator<Pair<DBTraceGuestPlatformMappedRange, AddressRange>> it =
			new OverlappingObjectIterator<DBTraceGuestPlatformMappedRange, AddressRange>(
				rangesByGuestAddress.values().iterator(), MappedRangeRanger.GUEST,
				guestSet.iterator(), OverlappingObjectIterator.ADDRESS_RANGE);
		AddressSet result = new AddressSet();
		while (it.hasNext()) {
			Pair<DBTraceGuestPlatformMappedRange, AddressRange> next = it.next();
			DBTraceGuestPlatformMappedRange entry = next.getLeft();
			AddressRange hostRange = next.getRight();
			result.add(entry.mapGuestToHost(hostRange));
		}
		return result;
	}

	/**
	 * Map the an address only if the entire range is contained in a single mapped range
	 * 
	 * @param guestMin the min address of the range to map
	 * @param guestMax the max address of the range to check
	 * @return the mapped min address
	 */
	public Address mapGuestToHost(Address guestMin, Address guestMax) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestPlatformMappedRange> floorEntry =
				rangesByGuestAddress.floorEntry(guestMin);
			if (floorEntry == null) {
				return null;
			}
			DBTraceGuestPlatformMappedRange range = floorEntry.getValue();
			if (!range.getGuestRange().contains(guestMax)) {
				return null;
			}
			return range.mapGuestToHost(guestMin);
		}
	}

	@Override
	public MemBuffer getMappedMemBuffer(long snap, Address guestAddress) {
		/*return new DBTraceGuestLanguageMappedMemBuffer(manager.trace.getMemoryManager(), this, snap,
			guestAddress);*/
		return new DumbMemBufferImpl(
			new DBTraceGuestPlatformMappedMemory(manager.trace.getMemoryManager(), this, snap),
			guestAddress);
	}

	@Override
	public InstructionSet mapGuestInstructionAddressesToHost(InstructionSet instructionSet) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Map<Address, InstructionBlock> blocksByNext = new HashMap<>();
			InstructionSet mappedSet = new InstructionSet(getAddressFactory());
			for (InstructionBlock block : instructionSet) {
				for (Instruction instruction : block) {
					Address hostAddr =
						mapGuestToHost(instruction.getAddress(), instruction.getMaxAddress());
					if (hostAddr == null) {
						continue; // TODO: Or illegal argument?
					}
					// TODO: Check if the block is broken across guest mappings.
					// TODO:    Should probably not allow it.

					// TODO: This will probably mess up all of its fall-through/target calculation....
					Instruction mappedIntruction;
					try {
						mappedIntruction = new PseudoInstruction(hostAddr,
							instruction.getPrototype(), instruction, instruction);
					}
					catch (AddressOverflowException e) {
						throw new AssertionError(e);
					}
					InstructionBlock addTo = blocksByNext.remove(hostAddr);
					if (addTo == null) {
						addTo = new InstructionBlock(hostAddr);
					}
					addTo.addInstruction(mappedIntruction);
					Address next = addTo.getMaxAddress().next();
					if (next != null) {
						blocksByNext.put(next, addTo);
					}
				}
			}
			blocksByNext.values().forEach(mappedSet::addBlock);
			return mappedSet;
		}
	}
}
