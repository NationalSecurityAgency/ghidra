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
package ghidra.trace.database.language;

import java.util.*;
import java.util.Map.Entry;

import com.google.common.collect.Range;

import db.DBRecord;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.trace.database.DBTraceUtils.LanguageIDDBFieldCodec;
import ghidra.trace.model.language.TraceGuestLanguage;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceGuestLanguage extends DBAnnotatedObject implements TraceGuestLanguage {
	public static final String TABLE_NAME = "Languages";

	static final String LANGID_COLUMN_NAME = "ID";
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

	private final DBTraceLanguageManager manager;

	private Language guestLanguage;

	protected final NavigableMap<Address, DBTraceGuestLanguageMappedRange> rangesByHostAddress =
		new TreeMap<>();
	protected final AddressSet hostAddressSet = new AddressSet();

	protected final NavigableMap<Address, DBTraceGuestLanguageMappedRange> rangesByGuestAddress =
		new TreeMap<>();
	protected final AddressSet guestAddressSet = new AddressSet();

	public DBTraceGuestLanguage(DBTraceLanguageManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	void setLanguage(Language language) {
		this.guestLanguage = language;
		this.langID = language.getLanguageID();
		this.version = language.getVersion();
		this.minorVersion = language.getMinorVersion();
		update(LANGID_COLUMN, VERSION_COLUMN, MINOR_VERSION_COLUMN);
	}

	protected void deleteMappedRange(DBTraceGuestLanguageMappedRange range, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			manager.trace.getCodeManager()
					.clearLanguage(Range.all(), range.getHostRange(),
						(int) getKey(), monitor);
			manager.rangeMappingStore.delete(range);
			AddressRange hostRange = range.getHostRange();
			AddressRange guestRange = range.getGuestRange();
			rangesByHostAddress.remove(hostRange.getMinAddress());
			rangesByGuestAddress.remove(guestRange.getMinAddress());
			hostAddressSet.delete(hostRange);
			guestAddressSet.delete(guestRange);
		}
	}

	protected void doGetLanguage(LanguageService langServ)
			throws LanguageNotFoundException, VersionException {
		this.guestLanguage = langServ.getLanguage(langID);
		if (version != guestLanguage.getVersion() ||
			minorVersion != guestLanguage.getMinorVersion()) {
			throw new VersionException(); // TODO Upgrade
		}
	}

	@Override
	public Language getLanguage() {
		return guestLanguage;
	}

	@Override
	public void delete(TaskMonitor monitor) throws CancelledException {
		manager.deleteGuestLanguage(this, monitor);
	}

	@Override
	public DBTraceGuestLanguageMappedRange addMappedRange(Address hostStart, Address guestStart,
			long length) throws AddressOverflowException {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			Address hostEnd = hostStart.addNoWrap(length - 1);
			if (hostAddressSet.intersects(hostStart, hostEnd)) {
				// TODO: Check for compatibility and extend?
				throw new IllegalArgumentException(
					"Range overlaps existing host mapped range(s) for this guest language");
			}
			Address guestEnd = guestStart.addNoWrap(length - 1);
			if (guestAddressSet.intersects(guestStart, guestEnd)) {
				throw new IllegalArgumentException("Range overlaps existing guest mapped range(s)");
			}
			DBTraceGuestLanguageMappedRange mappedRange = manager.rangeMappingStore.create();
			mappedRange.set(hostStart, guestLanguage, guestStart, length);
			rangesByHostAddress.put(hostStart, mappedRange);
			rangesByGuestAddress.put(guestStart, mappedRange);
			hostAddressSet.add(mappedRange.getHostRange());
			guestAddressSet.add(mappedRange.getGuestRange());
			return mappedRange;
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
			Entry<Address, DBTraceGuestLanguageMappedRange> floorEntry =
				rangesByHostAddress.floorEntry(hostAddress);
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapHostToGuest(hostAddress);
		}
	}

	@Override
	public Address mapGuestToHost(Address guestAddress) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Entry<Address, DBTraceGuestLanguageMappedRange> floorEntry =
				rangesByGuestAddress.floorEntry(guestAddress);
			if (floorEntry == null) {
				return null;
			}
			return floorEntry.getValue().mapGuestToHost(guestAddress);
		}
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
			Entry<Address, DBTraceGuestLanguageMappedRange> floorEntry =
				rangesByGuestAddress.floorEntry(guestMin);
			if (floorEntry == null) {
				return null;
			}
			DBTraceGuestLanguageMappedRange range = floorEntry.getValue();
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
			new DBTraceGuestLanguageMappedMemory(manager.trace.getMemoryManager(), this, snap),
			guestAddress);
	}

	@Override
	public InstructionSet mapGuestInstructionAddressesToHost(InstructionSet instructionSet) {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			Map<Address, InstructionBlock> blocksByNext = new HashMap<>();
			InstructionSet mappedSet = new InstructionSet(guestLanguage.getAddressFactory());
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
