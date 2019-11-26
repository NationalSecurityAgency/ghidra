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
package ghidra.program.database.map;

import java.io.IOException;
import java.util.*;

import db.DBConstants;
import db.DBHandle;
import ghidra.program.database.map.AddressMapDBAdapter.AddressMapEntry;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class used to map addresses to longs and longs to addresses. Several different encodings
 * are depending on the nature of the address to be converted.
 * The upper 4 bits in the long are used to specify the encoding used. Currently the encoding are:
 * 0 - use the original ghidra encoding - used for backwards compatibility.
 * 1 - absolute encoding - ignores the image base - used only by the memory map.
 * 2 - relocatable - most common encoding - allows address to move with the image base.
 * 3 - register - used to encode register addresses
 * 4 - stack - used to encode stack addresses (includes namespace information to make them unique between functions)
 * 5 - external - used to encode addresses in another program
 * 15 - no address - used to represent the null address or a meaningless address.
 */

public class AddressMapDB implements AddressMap {

	final static int ADDR_TYPE_SIZE = 4;
	private final static long ADDR_TYPE_SHIFT = 64 - ADDR_TYPE_SIZE;
	private final static int ADDR_TYPE_MASK = (1 << ADDR_TYPE_SIZE) - 1;

	//private final static long ID_OFFSET_MASK = (1 << ADDR_TYPE_SHIFT) - 1;

	final static int ADDR_OFFSET_SIZE = 32;
	private final static long MAX_OFFSET = (1L << ADDR_OFFSET_SIZE) - 1;
	final static long ADDR_OFFSET_MASK = MAX_OFFSET;
	final static long BASE_MASK = ~ADDR_OFFSET_MASK;

	private final static int HASH_OFFSET_SIZE = AddressSpace.HASH_SPACE.getSize(); // 60
	private final static long HASH_OFFSET_MASK = (1L << HASH_OFFSET_SIZE) - 1;

	private final static int ID_SIZE = 64 - ADDR_TYPE_SIZE - ADDR_OFFSET_SIZE;
	private final static int ID_MASK = (1 << ID_SIZE) - 1;

	private final static int OLD_ADDRESS_KEY_TYPE = 0x0;
	private final static int ABSOLUTE_ADDR_TYPE = 0x1; // uses base ID to identify 32-bit segment base address
	private final static int RELOCATABLE_ADDR_TYPE = 0x2; // uses base ID to identify 32-bit segment base address
	private final static int REGISTER_ADDR_TYPE = 0x3;
	private final static int STACK_ADDR_TYPE = 0x4;
	private final static int EXTERNAL_ADDR_TYPE = 0x5;
	private final static int VARIABLE_ADDR_TYPE = 0x6;
	private final static int HASH_ADDR_TYPE = 0x7; // corresponds to static HASH_SPACE with 60-bit offset

	private final static int NO_ADDR_TYPE = 0xf;

	private final static long RELOCATABLE_ADDR_TYPE_LONG =
		(long) RELOCATABLE_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long ABSOLUTE_ADDR_TYPE_LONG =
		(long) ABSOLUTE_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long REGISTER_ADDR_TYPE_LONG =
		(long) REGISTER_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long STACK_ADDR_TYPE_LONG = (long) STACK_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long EXTERNAL_ADDR_TYPE_LONG =
		(long) EXTERNAL_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long VARIABLE_ADDR_TYPE_LONG =
		(long) VARIABLE_ADDR_TYPE << ADDR_TYPE_SHIFT;
	private final static long HASH_ADDR_TYPE_LONG = (long) HASH_ADDR_TYPE << ADDR_TYPE_SHIFT;

	private AddressFactory addrFactory;
	private boolean readOnly;
	private AddressMap oldAddrMap;
	private boolean useOldAddrMap = false;
	private AddressSpace defaultAddrSpace;
	private AddressMapDBAdapter adapter;
	private Address[] baseAddrs; // these are normalized addrs
	private Address[] sortedBaseStartAddrs; // these are normalized addrs
	private Address[] sortedBaseEndAddrs;
	private List<KeyRange> allKeyRanges; // all existing key ranges (includes non-absolute memory, and external space) 
	private HashMap<Address, Integer> addrToIndexMap = new HashMap<Address, Integer>();

	private long baseImageOffset; // pertains to default address space only
	private List<AddressRange> segmentedRanges; // when using segmented memory, this list contains	
	// the ranges for each memory block for normalization

	private static final long EXT_FROM_ADDRESS_LONG = -2;

	/**
	 * Index Operation: get index match or create if needed
	 * @see #getBaseAddressIndex(Address, boolean, int)
	 */
	private static final int INDEX_CREATE = 0; // get index match or create if needed
	private static final int INDEX_MATCH = 1; // get index match only or Integer.MIN_VALUE if not found
	private static final int INDEX_MATCH_OR_NEXT = 2; // get index match if found, else next or Integer.MIN_VALUE if next not found
	private static final int INDEX_MATCH_OR_PREVIOUS = 3; // get index match if found, else previous or Integer.MIN_VALUE if previous not found

	/**
	 * Comparator used to search the sorted normalized base address list with a de-normalized address.
	 */
	private Comparator<Address> normalizingAddressComparator = new Comparator<Address>() {
		@Override
		public int compare(Address normalizedAddr, Address addr) {
			// Handle baseOffset shift for DefaultAddressSpace only
			AddressSpace space = addr.getAddressSpace();
			int comp = normalizedAddr.getAddressSpace().compareTo(space);
			if (comp == 0) {
				// Same address space - assumes unsigned space
				long maxOffset = space.getMaxAddress().getOffset();
				long otherOffset = addr.getOffset() - baseImageOffset;
				long offset = normalizedAddr.getOffset();
				if (space.getSize() == 64) {
					// Address space offsets are 64-bit unsigned
					// wrapping of otherOffset handled automatically
					if (offset < 0 && otherOffset >= 0) {
						return 1;
					}
					else if (offset >= 0 && otherOffset < 0) {
						return -1;
					}
				}
				else if (otherOffset < 0) {
					// wrap normalized otherOffset within space for spaces smaller than 64-bits
					otherOffset += maxOffset + 1;
				}
				long diff = offset - otherOffset;
				if (diff > 0) {
					return 1;
				}
				if (diff < 0) {
					return -1;
				}
			}
			return comp;
		}
	};

	/**
	 * Comparator used to identify if an addr occurs before or after the 
	 * start of a key range.
	 */
	private Comparator<Object> addressInsertionKeyRangeComparator = new Comparator<Object>() {
		@Override
		public int compare(Object keyRangeObj, Object addrObj) {
			KeyRange range = (KeyRange) keyRangeObj;
			Address addr = (Address) addrObj;

			Address min = decodeAddress(range.minKey);
			if (min.compareTo(addr) > 0) {
				return 1;
			}

			Address max = decodeAddress(range.maxKey);
			if (max.compareTo(addr) < 0) {
				return -1;
			}
			return 0;
		}
	};
	private static Comparator<Object> ADDRESS_RANGE_COMPARATOR = new Comparator<Object>() {
		@Override
		public int compare(Object o1, Object o2) {
			AddressRange range = (AddressRange) o1;
			Address addr = (Address) o2;
			if (range.contains(addr)) {
				return 0;
			}
			return range.getMinAddress().compareTo(addr);
		}
	};

	/**
	 * Constructs a new AddressMapDB object
	 * @param handle the handle to the database
	 * @param openMode the mode that program was opened.
	 * @param factory the address factory containing all the address spaces for the program.
	 * @param baseImageOffset the current image base offset.
	 * @param monitor the progress monitory used for upgrading.
	 * @throws IOException thrown if a dabase io error occurs.
	 * @throws VersionException if the database version does not match the expected version.
	 */
	public AddressMapDB(DBHandle handle, int openMode, AddressFactory factory, long baseImageOffset,
			TaskMonitor monitor) throws IOException, VersionException {
		this.readOnly = (openMode == DBConstants.READ_ONLY);
		this.addrFactory = factory;
		this.baseImageOffset = baseImageOffset;
		defaultAddrSpace = addrFactory.getDefaultAddressSpace();
		adapter = AddressMapDBAdapter.getAdapter(handle, openMode, addrFactory, monitor);
		oldAddrMap = (adapter.oldAddrMap != null) ? adapter.oldAddrMap : this;
		useOldAddrMap = (openMode == DBConstants.READ_ONLY && oldAddrMap != this);
		baseAddrs = adapter.getBaseAddresses(false);
		init(true);
	}

	/**
	 * Notification when the memory map changes.  If we are segemented, we need to update our
	 * list of address ranges used for address normalization.
	 * @param mem the changed memory map.
	 */
	public synchronized void memoryMapChanged(MemoryMapDB mem) {
		if (!(addrFactory.getDefaultAddressSpace() instanceof SegmentedAddressSpace)) {
			segmentedRanges = null;
			return; // if not segmented, we don't care
		}
		MemoryBlock[] blocks = mem.getBlocks();
		segmentedRanges = new ArrayList<AddressRange>(blocks.length);
		for (MemoryBlock block : blocks) {
			segmentedRanges.add(new AddressRangeImpl(block.getStart(), block.getEnd()));
		}
	}

	private void init(boolean rebuildAddrToIndexMap) {
		allKeyRanges = null;
		sortedBaseEndAddrs = new Address[baseAddrs.length];
		sortedBaseStartAddrs = new Address[baseAddrs.length];
		System.arraycopy(baseAddrs, 0, sortedBaseStartAddrs, 0, baseAddrs.length);
		Arrays.sort(sortedBaseStartAddrs);
		for (int i = 0; i < sortedBaseStartAddrs.length; i++) {
			long max = sortedBaseStartAddrs[i].getAddressSpace().getMaxAddress().getOffset();
			max = max < 0 ? MAX_OFFSET : Math.min(max, MAX_OFFSET);
			// Avoid use of add which fails for overlay addresses which have restricted min/max offsets
			long off = sortedBaseStartAddrs[i].getOffset() | max;
			sortedBaseEndAddrs[i] =
				sortedBaseStartAddrs[i].getAddressSpace().getAddressInThisSpaceOnly(off);
		}
		if (rebuildAddrToIndexMap) {
			addrToIndexMap.clear();
			for (int i = 0; i < baseAddrs.length; i++) {
				addrToIndexMap.put(baseAddrs[i], i);
			}
		}
	}

	@Override
	public synchronized void invalidateCache() throws IOException {
		if (!readOnly) {
			baseAddrs = adapter.getBaseAddresses(true);
			init(true);
		}
	}

	/**
	 * Returns an address map which may be used during the upgrade of old address
	 * encodings.  If the address map is up-to-date, then this method will return
	 * this instance of AddressMapDB.
	 */
	@Override
	public AddressMap getOldAddressMap() {
		return useOldAddrMap ? this : oldAddrMap;
	}

	@Override
	public boolean isUpgraded() {
		return getOldAddressMap() != this;
	}

	@Override
	public synchronized long getKey(Address addr, boolean create) {
		if (useOldAddrMap) {
			return oldAddrMap.getKey(addr, create);
		}
		try {
			return encodeRelative(addr, false, create ? INDEX_CREATE : INDEX_MATCH);
		}
		catch (IllegalArgumentException e) {
			return INVALID_ADDRESS_KEY;
		}
	}

	private boolean isInDefaultAddressSpace(Address addr) {
		return addr.getAddressSpace().equals(defaultAddrSpace);
	}

	private long getNormalizedOffset(Address addr) {
		// supports unsigned space only
		long offset = addr.getOffset() - baseImageOffset;
		long maxOffset = addr.getAddressSpace().getMaxAddress().getOffset();
		if (maxOffset > 0 && offset < 0) {
			// wrap normalized otherOffset within space
			return offset + maxOffset + 1;
		}
		return offset;
	}

	@Override
	public synchronized long getAbsoluteEncoding(Address addr, boolean create) {
		if (useOldAddrMap) {
			return oldAddrMap.getAbsoluteEncoding(addr, create);
		}
		return encodeAbsolute(addr, create ? INDEX_CREATE : INDEX_MATCH);
	}

	/**
	 * Get absolute key encoding for the specified address
	 * @param addr address
	 * @param indexOperation see INDEX_CREATE, INDEX_MATCH, INDEX_MATCH_OR_NEXT or INDEX_MATCH_OR_PREVIOUS
	 * @return address key or INVALID_ADDRESS_KEY if not found
	 */
	private long encodeAbsolute(Address addr, int indexOperation) {
		if (addr instanceof OldGenericNamespaceAddress) {
			return encodeOldNamespaceAddr((OldGenericNamespaceAddress) addr);
		}
		switch (addr.getAddressSpace().getType()) {
			case AddressSpace.TYPE_UNKNOWN:
				if (addr.isHashAddress()) {
					// 60-bit hash address
					return HASH_ADDR_TYPE_LONG | addr.getOffset();
				}
			case AddressSpace.TYPE_RAM:
			case AddressSpace.TYPE_CODE:
			case AddressSpace.TYPE_DELETED:
			case AddressSpace.TYPE_OTHER:
				int baseIndex = getBaseAddressIndex(addr, false, indexOperation);
				long offset;
				if (baseIndex < 0) {
					if (baseIndex == Integer.MIN_VALUE) {
						// base address not found
						return INVALID_ADDRESS_KEY;
					}
					baseIndex = -baseIndex - 1;
					if (indexOperation == INDEX_MATCH_OR_PREVIOUS) {
						// last address of previous base segment
						offset = MAX_OFFSET;
					}
					else if (indexOperation == INDEX_MATCH_OR_NEXT) {
						// first address of next base segment
						offset = 0;
					}
					else {
						throw new AssertException("unexpected negative base index");
					}
				}
				else {
					offset = addr.getOffset() & ADDR_OFFSET_MASK;
				}
				return ABSOLUTE_ADDR_TYPE_LONG | ((long) baseIndex << ADDR_OFFSET_SIZE) | offset;

			case AddressSpace.TYPE_VARIABLE:
				return VARIABLE_ADDR_TYPE_LONG | (addr.getOffset() & ADDR_OFFSET_MASK);

			case AddressSpace.TYPE_REGISTER:
				return REGISTER_ADDR_TYPE_LONG | (addr.getOffset() & ADDR_OFFSET_MASK);

			case AddressSpace.TYPE_STACK:
				return STACK_ADDR_TYPE_LONG | (addr.getOffset() & ADDR_OFFSET_MASK);

			case AddressSpace.TYPE_EXTERNAL:
				return EXTERNAL_ADDR_TYPE_LONG | (addr.getOffset() & ADDR_OFFSET_MASK);

			case AddressSpace.TYPE_NONE:
				if (addr == Address.EXT_FROM_ADDRESS) {
					return EXT_FROM_ADDRESS_LONG;
				}
				return INVALID_ADDRESS_KEY;
		}
		throw new IllegalArgumentException("Address type can not be encoded");
	}

	/**
	 * Get base address index
	 * @param addr address
	 * @param normalize if true image base offset will be applied to addr
	 * @param indexOperation see INDEX_CREATE, INDEX_MATCH, INDEX_MATCH_OR_NEXT or INDEX_MATCH_OR_PREVIOUS
	 * @return base address index or Integer.MIN_VALUE if index not found and create is false.  A negative 
	 * value other than Integer.MIN_VALUE indicates a NEXT or PREVIOUS base index = -(return_value)-1.
	 */
	private int getBaseAddressIndex(Address addr, boolean normalize, int indexOperation) {

		long normalizedOffset = normalize ? getNormalizedOffset(addr) : addr.getOffset();
		long normalizedBaseOffset = normalizedOffset & BASE_MASK;

		AddressSpace space = addr.getAddressSpace();
		Address tBase = space.getAddressInThisSpaceOnly(normalizedBaseOffset);
		Integer tIndex = addrToIndexMap.get(tBase);
		if (tIndex != null) {
			return tIndex;
		}
		else if (indexOperation == INDEX_MATCH) {
			return Integer.MIN_VALUE;
		}

		int search = normalize
				? Arrays.binarySearch(sortedBaseStartAddrs, addr, normalizingAddressComparator)
				: Arrays.binarySearch(sortedBaseStartAddrs, addr);

		if (search < 0) {
			search = -search - 2;
		}
		if (search >= 0) {
			// Check for match
			Address base = sortedBaseStartAddrs[search];
			if (base.hasSameAddressSpace(addr) && normalizedBaseOffset == base.getOffset()) {
				int index = addrToIndexMap.get(base);
				return index;
			}
		}
		if (indexOperation == INDEX_MATCH_OR_PREVIOUS) {
			if (search >= 0) {
				Address base = sortedBaseStartAddrs[search];
				int index = addrToIndexMap.get(base);
				return -index - 1;
			}
		}
		if (indexOperation == INDEX_MATCH_OR_NEXT) {
			int nextIndex = search + 1;
			if (nextIndex < sortedBaseStartAddrs.length) {
				Address base = sortedBaseStartAddrs[nextIndex];
				int index = addrToIndexMap.get(base);
				return -index - 1;
			}
		}
		if (indexOperation != INDEX_CREATE) {
			// existing base address entry not found - can not create
			return Integer.MIN_VALUE;
		}

		// A new address map entry is required
		checkAddressSpace(addr.getAddressSpace());
		int index = baseAddrs.length;
		if (readOnly) {
			// Create new base without modifying database
			Address[] newBaseAddrs = new Address[baseAddrs.length + 1];
			System.arraycopy(baseAddrs, 0, newBaseAddrs, 0, baseAddrs.length);
			newBaseAddrs[index] =
				addr.getAddressSpace().getAddressInThisSpaceOnly(normalizedBaseOffset);
			baseAddrs = newBaseAddrs;
		}
		else {
			baseAddrs = adapter.addBaseAddress(addr, normalizedBaseOffset);
			if (baseAddrs.length == 101) {
				// TODO: Added to identify rogue Analyzers which cause too many segments to be created
				// Leaving out stack trace because many object files really do have this many segments
				Msg.warn(this, "More than 100 address segments have been created!", null);
			}
		}
		addrToIndexMap.put(baseAddrs[index], index);
		init(false); // re-sorts baseAddrs
		return index;
	}

	void checkAddressSpace(AddressSpace addrSpace) {
		AddressSpace[] spaces = addrFactory.getPhysicalSpaces();
		for (AddressSpace space : spaces) {
			if (addrSpace.equals(space)) {
				return;
			}
		}
		if (addrSpace.getPhysicalSpace() != AddressSpace.OTHER_SPACE) { // not physical - but always exists in program
			throw new IllegalArgumentException("Address space not found in program");
		}
	}

	@Override
	public synchronized Address decodeAddress(long value) {
		return decodeAddress(value, true);
	}

	/**
	 * Returns the address that was used to generate the given long key. (If the image base was
	 * moved, then a different address is returned unless the value was encoded using the
	 * "absoluteEncoding" method
	 * @param value the long value to convert to an address.
	 * @param useMemorySegmentation if true and the program's default address space is segmented (i.e., SegmentedAddressSpace).
	 * the address returned will be normalized to defined segmented memory blocks if possible.  This parameter should 
	 * generally always be true except when used by the Memory map objects to avoid recursion problems.
	 */
	public synchronized Address decodeAddress(long value, boolean useMemorySegmentation) {
		Address addr;
		try {
			addr = decode(value);
			if (useMemorySegmentation) {
				addr = normalize(addr);
			}
		}
		catch (AddressOutOfBoundsException e) {
			//Err.error(this, e.getMessage());
			addr = Address.NO_ADDRESS;
		}
		return addr;
	}

	private Address normalize(Address addr) {
		if (segmentedRanges == null || !(addr instanceof SegmentedAddress)) {
			return addr;
		}

		int index = Collections.binarySearch(segmentedRanges, addr, ADDRESS_RANGE_COMPARATOR);
		if (index >= 0) {
			SegmentedAddress segAddr = (SegmentedAddress) addr;
			int seg = ((SegmentedAddress) segmentedRanges.get(index).getMinAddress()).getSegment();
			return segAddr.normalize(seg);
		}
		return addr;
	}

	private Address decode(long value) {
		if (useOldAddrMap) {
			return oldAddrMap.decodeAddress(value);
		}
		int type = (int) ((value >> ADDR_TYPE_SHIFT) & ADDR_TYPE_MASK);
		switch (type) {
			case OLD_ADDRESS_KEY_TYPE:
				return addrFactory.oldGetAddressFromLong(value);
			case ABSOLUTE_ADDR_TYPE:
				int baseIndex = (int) ((value >> ADDR_OFFSET_SIZE) & ID_MASK);
				long offset = value & ADDR_OFFSET_MASK;
				try {
					return baseAddrs[baseIndex].add(offset);
				}
				catch (ArrayIndexOutOfBoundsException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					throw e;
				}
			case RELOCATABLE_ADDR_TYPE:
				baseIndex = (int) ((value >> ADDR_OFFSET_SIZE) & ID_MASK);
				offset = value & ADDR_OFFSET_MASK;
				if (baseIndex >= baseAddrs.length) {
					return Address.NO_ADDRESS;
				}
				Address base = baseAddrs[baseIndex];
				if (base.getAddressSpace().equals(defaultAddrSpace)) {
					offset += baseImageOffset;
				}
				return baseAddrs[baseIndex].addWrapSpace(offset);

			case VARIABLE_ADDR_TYPE:
				offset = value & ADDR_OFFSET_MASK;
				return AddressSpace.VARIABLE_SPACE.getAddress(offset);

			case REGISTER_ADDR_TYPE:
				int nameSpaceID = (int) ((value >> ADDR_OFFSET_SIZE) & ID_MASK);
				offset = value & ADDR_OFFSET_MASK;
				if (nameSpaceID != Namespace.GLOBAL_NAMESPACE_ID) {
					// needed for upgrade
					return new OldGenericNamespaceAddress(addrFactory.getRegisterSpace(), offset,
						nameSpaceID);
				}
				return addrFactory.getRegisterSpace().getAddress(offset);

			case STACK_ADDR_TYPE:
				nameSpaceID = (int) ((value >> ADDR_OFFSET_SIZE) & ID_MASK);
				// integer cast is required to force sign extension of masked value
				offset = (int) (value & ADDR_OFFSET_MASK);
				AddressSpace stackSpace = addrFactory.getStackSpace();
				if (nameSpaceID != Namespace.GLOBAL_NAMESPACE_ID) {
					// needed for upgrade
					try {
						return new OldGenericNamespaceAddress(stackSpace, offset, nameSpaceID);
					}
					catch (AddressOutOfBoundsException e) {
						// Recover bad stack address as best we can (used to be a common 32-bit stack space)
						return new OldGenericNamespaceAddress(stackSpace,
							truncateStackOffset(offset, stackSpace), nameSpaceID);
					}
				}
				try {
					return stackSpace.getAddress(offset);
				}
				catch (AddressOutOfBoundsException e) {
					// Recover bad stack address as best we can (used to be a common 32-bit stack space)
					return stackSpace.getAddress(truncateStackOffset(offset, stackSpace));
				}
			case EXTERNAL_ADDR_TYPE:
				nameSpaceID = (int) ((value >> ADDR_OFFSET_SIZE) & ID_MASK);
				offset = value & ADDR_OFFSET_MASK;
				if (nameSpaceID != Namespace.GLOBAL_NAMESPACE_ID) {
					// needed for upgrade
					return new OldGenericNamespaceAddress(AddressSpace.EXTERNAL_SPACE, offset,
						nameSpaceID);
				}
				return AddressSpace.EXTERNAL_SPACE.getAddress(offset);

			case HASH_ADDR_TYPE:
				offset = value & HASH_OFFSET_MASK;
				return AddressSpace.HASH_SPACE.getAddress(offset);

			case NO_ADDR_TYPE:
				if (value == EXT_FROM_ADDRESS_LONG) {
					return Address.EXT_FROM_ADDRESS;
				}
				return Address.NO_ADDRESS;
		}
		throw new RuntimeException("Unsupported address type: " + type);
	}

	/**
	 * Stack space changed from a common 32-bit space to a compiler-specific
	 * stack space.  This makes bad stack addresses which previously existed
	 * impossible to decode.  Instead of return NO_ADDRESS, we will simply truncate such 
	 * bad stack offsets to the MIN or MAX offsets.
	 * @param offset
	 * @param stackSpace
	 * @return
	 */
	private long truncateStackOffset(long offset, AddressSpace stackSpace) {
		return offset < 0 ? stackSpace.getMinAddress().getOffset()
				: stackSpace.getMaxAddress().getOffset();
	}

	@Override
	public boolean hasSameKeyBase(long addrKey1, long addrKey2) {
		return (addrKey1 >> ADDR_OFFSET_SIZE) == (addrKey2 >> ADDR_OFFSET_SIZE);
	}

	@Override
	public boolean isKeyRangeMax(long addrKey) {
		return (addrKey & ADDR_OFFSET_MASK) == MAX_OFFSET;
	}

	@Override
	public boolean isKeyRangeMin(long addrKey) {
		return (addrKey & ADDR_OFFSET_MASK) == 0;
	}

	private long encodeRelative(Address addr, boolean addrIsNormalized, int indexOperation) {
		AddressSpace addressSpace = addr.getAddressSpace();
		int type = addressSpace.getType();
		switch (type) {
			case AddressSpace.TYPE_UNKNOWN:
				if (addr.isHashAddress()) {
					// 60-bit hash address
					return HASH_ADDR_TYPE_LONG | addr.getOffset();
				}
			case AddressSpace.TYPE_RAM:
			case AddressSpace.TYPE_CODE:
			case AddressSpace.TYPE_DELETED:
			case AddressSpace.TYPE_OTHER:
				boolean normalize = !addrIsNormalized && isInDefaultAddressSpace(addr);
				int baseIndex = getBaseAddressIndex(addr, normalize, indexOperation);
				long offset;
				if (baseIndex < 0) {
					if (baseIndex == Integer.MIN_VALUE) {
						// base address not found
						return INVALID_ADDRESS_KEY;
					}
					baseIndex = -baseIndex - 1;
					if (indexOperation == INDEX_MATCH_OR_PREVIOUS) {
						// last address of previous base segment
						offset = MAX_OFFSET;
					}
					else if (indexOperation == INDEX_MATCH_OR_NEXT) {
						// first address of next base segment
						offset = 0;
					}
					else {
						throw new AssertException("unexpected negative base index");
					}
				}
				else {
					offset = normalize ? getNormalizedOffset(addr) : addr.getOffset();
				}
				return RELOCATABLE_ADDR_TYPE_LONG | ((long) baseIndex << ADDR_OFFSET_SIZE) |
					(offset & ADDR_OFFSET_MASK);
			default:
				return encodeAbsolute(addr, indexOperation);
		}
	}

	/**
	 * Provide absolute encoding of an old namespace address for upgrade use.
	 * @param addr old namespace address for stack, register or external
	 * @return encoded address key
	 */
	private long encodeOldNamespaceAddr(OldGenericNamespaceAddress addr) {
		switch (addr.getAddressSpace().getType()) {
			case AddressSpace.TYPE_STACK:
				return STACK_ADDR_TYPE_LONG | (addr.getNamespaceID() << ADDR_OFFSET_SIZE) |
					(addr.getOffset() & ADDR_OFFSET_MASK);
			case AddressSpace.TYPE_REGISTER:
				return REGISTER_ADDR_TYPE_LONG | (addr.getNamespaceID() << ADDR_OFFSET_SIZE) |
					(addr.getOffset() & ADDR_OFFSET_MASK);
			case AddressSpace.TYPE_EXTERNAL:
				return EXTERNAL_ADDR_TYPE_LONG | (addr.getNamespaceID() << ADDR_OFFSET_SIZE) |
					(addr.getOffset() & ADDR_OFFSET_MASK);
		}
		throw new IllegalArgumentException("Address can not be encoded");
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addrFactory;
	}

	@Override
	public void setImageBase(Address base) {
		if (useOldAddrMap) {
			throw new IllegalStateException();
		}
		if (base instanceof SegmentedAddress) {
			if (((SegmentedAddress) base).getSegmentOffset() != 0) {
				throw new IllegalArgumentException(
					"Segmented base address must have a 0 segment offset");
			}
		}
		baseImageOffset = base.getOffset();
	}

	@Override
	public synchronized int getModCount() {
		return baseAddrs.length;
	}

	@Override
	public int findKeyRange(List<KeyRange> keyRangeList, Address addr) {
		// TODO: Will not handle mixed list of relative and absolute key ranges
		if (addr == null) {
			return -1;
		}
		return Collections.binarySearch(keyRangeList, addr, addressInsertionKeyRangeComparator);
	}

	@Override
	public List<KeyRange> getKeyRanges(Address start, Address end, boolean create) {
		return getKeyRanges(start, end, false, create);
	}

	@Override
	public List<KeyRange> getKeyRanges(AddressSetView set, boolean create) {
		return getKeyRanges(set, false, create);
	}

	@Override
	public synchronized List<KeyRange> getKeyRanges(Address start, Address end, boolean absolute,
			boolean create) {
		if (!start.hasSameAddressSpace(end)) {
			return getKeyRanges(addrFactory.getAddressSet(start, end), create);
		}
		if (useOldAddrMap) {
			return oldAddrMap.getKeyRanges(start, end, absolute);
		}
		ArrayList<KeyRange> keyRangeList = new ArrayList<KeyRange>();
		addKeyRanges(keyRangeList, start, end, absolute, create);
		return keyRangeList;
	}

	private AddressSetView getAllMemoryAndExternalAddresses() {
		AddressSet fullSet = new AddressSet();
		for (AddressSpace space : addrFactory.getAllAddressSpaces()) {
			if (space.isMemorySpace() || space.isExternalSpace()) {
				fullSet.addRange(space.getMinAddress(), space.getMaxAddress());
			}
		}
		return fullSet;
	}

	@Override
	public synchronized List<KeyRange> getKeyRanges(AddressSetView set, boolean absolute,
			boolean create) {

		if (useOldAddrMap) {
			return oldAddrMap.getKeyRanges(set, absolute, create);
		}
		ArrayList<KeyRange> keyRangeList = new ArrayList<KeyRange>();
		if (set == null) {
			if (create) {
				throw new IllegalArgumentException(
					"Restricted address set must be specified when iterating over address keys with create enabled");
			}
			if (!absolute) {
				if (allKeyRanges == null) {
					getKeyRangesForAddressSet(getAllMemoryAndExternalAddresses(), false, false,
						keyRangeList);
					allKeyRanges = keyRangeList;
				}
				return new ArrayList<KeyRange>(allKeyRanges);
			}
			set = getAllMemoryAndExternalAddresses();
		}
		getKeyRangesForAddressSet(set, absolute, create, keyRangeList);
		return keyRangeList;
	}

	private void getKeyRangesForAddressSet(AddressSetView set, boolean absolute, boolean create,
			ArrayList<KeyRange> keyRangeList) {
		AddressRangeIterator it = set.getAddressRanges();
		while (it.hasNext()) {
			AddressRange range = it.next();
			addKeyRanges(keyRangeList, range.getMinAddress(), range.getMaxAddress(), absolute,
				create);
		}
	}

	/**
	 * Create all memory base segments within the specified range.
	 * NOTE: minAddress and maxAddress must have the same address space!
	 * @param minAddress
	 * @param maxAddress
	 */
	private void createBaseSegments(Address minAddress, Address maxAddress) {

		long minBase;
		long maxBase;

		if (isInDefaultAddressSpace(minAddress)) {
			minBase = getNormalizedOffset(minAddress) & BASE_MASK;
			maxBase = getNormalizedOffset(maxAddress) & BASE_MASK;
		}
		else {
			minBase = minAddress.getOffset() & BASE_MASK;
			maxBase = maxAddress.getOffset() & BASE_MASK;
		}

		for (long base = minBase; base <= maxBase; base += (MAX_OFFSET + 1)) {
			getBaseAddressIndex(minAddress.getNewAddress(base), false, INDEX_CREATE);
		}
	}

	/**
	 * Add simple key ranges where the address range lies within a single base segment for a single space.
	 * NOTE: start and end addresses must have the same address space!
	 * @param keyRangeList
	 * @param start
	 * @param end
	 * @param absolute
	 * @param create
	 */
	private void addKeyRanges(List<KeyRange> keyRangeList, Address start, Address end,
			boolean absolute, boolean create) {
		if (start.isMemoryAddress()) {
			if (create) {
				createBaseSegments(start, end);
			}
			Address normalizedStart = absolute ? start : getShiftedAddr(start);
			Address normalizedEnd = absolute ? end : getShiftedAddr(end);
			if (normalizedStart.compareTo(normalizedEnd) > 0) {
				AddressSpace space = normalizedStart.getAddressSpace();
				addNormalizedRange(keyRangeList, normalizedStart, space.getMaxAddress(), absolute);
				addNormalizedRange(keyRangeList, space.getMinAddress(), normalizedEnd, absolute);
			}
			else {
				addNormalizedRange(keyRangeList, normalizedStart, normalizedEnd, absolute);
			}
		}
		else {
			// WARNING! intended for stack and other non-memory spaces which must be 32-bit addressable or smaller
			long minKey = encodeRelative(start, false, INDEX_MATCH);
			long maxKey = encodeRelative(end, false, INDEX_MATCH);
			keyRangeList.add(new KeyRange(minKey, maxKey));
		}
	}

	private void addNormalizedRange(List<KeyRange> keyRangeList, Address normalizedStart,
			Address normalizedEnd, boolean absolute) {

		// Try optimized single range approach first
		long maxKey;
		long minKey = absolute ? encodeAbsolute(normalizedStart, INDEX_MATCH)
				: encodeRelative(normalizedStart, true, INDEX_MATCH);
		if (minKey != INVALID_ADDRESS_KEY) {
			maxKey = absolute ? encodeAbsolute(normalizedEnd, INDEX_MATCH)
					: encodeRelative(normalizedEnd, true, INDEX_MATCH);
			if (maxKey != INVALID_ADDRESS_KEY && (minKey & BASE_MASK) == (maxKey & BASE_MASK)) {
				keyRangeList.add(new KeyRange(minKey, maxKey));
				return;
			}
		}

		// Try multi-range approach
		int index = Arrays.binarySearch(sortedBaseStartAddrs, normalizedStart);
		if (index < 0) {
			index = -index - 2;
		}
		if (index < 0) {
			index++;
		}
		while (index < sortedBaseStartAddrs.length &&
			normalizedEnd.compareTo(sortedBaseStartAddrs[index]) >= 0) {
			Address addr1 = max(normalizedStart, sortedBaseStartAddrs[index]);
			Address addr2 = min(normalizedEnd, sortedBaseEndAddrs[index]);
			if (addr1.compareTo(addr2) <= 0) {
				// Collapse range where minKey and maxKey fall within existing base segments
				minKey = absolute ? encodeAbsolute(addr1, INDEX_MATCH_OR_NEXT)
						: encodeRelative(addr1, true, INDEX_MATCH_OR_NEXT);
				maxKey = absolute ? encodeAbsolute(addr2, INDEX_MATCH_OR_PREVIOUS)
						: encodeRelative(addr2, true, INDEX_MATCH_OR_PREVIOUS);
				if (minKey != INVALID_ADDRESS_KEY && maxKey != INVALID_ADDRESS_KEY) {
					keyRangeList.add(new KeyRange(minKey, maxKey));
				}
			}
			index++;
		}
	}

	private Address min(Address a1, Address a2) {
		return a1.compareTo(a2) < 0 ? a1 : a2;
	}

	private Address max(Address a1, Address a2) {
		return a1.compareTo(a2) < 0 ? a2 : a1;
	}

	private Address getShiftedAddr(Address addr) {
		if (addr.getAddressSpace().equals(defaultAddrSpace)) {
			return addr.subtractWrapSpace(baseImageOffset);
		}
		return addr;
	}

	@Override
	public Address getImageBase() {
		if (defaultAddrSpace instanceof SegmentedAddressSpace) {
			return ((SegmentedAddressSpace) defaultAddrSpace).getAddress(
				(int) (baseImageOffset >> 4), 0);
		}
		return defaultAddrSpace.getAddress(baseImageOffset);
	}

	@Override
	public synchronized void setLanguage(Language newLanguage, AddressFactory addrFactory,
			LanguageTranslator translator) throws IOException {

		List<AddressMapEntry> entries = adapter.getEntries();
		List<AddressMapEntry> newEntries = new ArrayList<AddressMapEntry>();

		AddressFactory oldAddressFactory = this.addrFactory;

		this.addrFactory = addrFactory;
		defaultAddrSpace = addrFactory.getDefaultAddressSpace();

		adapter.clearAll();
		adapter.setAddressFactory(addrFactory);

		for (AddressMapEntry entry : entries) {
			if (entry.deleted) {
				newEntries.add(entry);
			}
			else {
				AddressSpace oldSpace = oldAddressFactory.getAddressSpace(entry.name);
				if (oldSpace != null && oldSpace.isLoadedMemorySpace() &&
					!oldSpace.isOverlaySpace()) {
					AddressSpace newSpace = translator.getNewAddressSpace(entry.name);
					if (newSpace != null && (entry.segment == 0 || newSpace.getSize() > 32)) {
						entry.name = newSpace.getName();
					}
					else {
						entry.deleted = true;
					}
				}
				newEntries.add(entry);
			}
		}
		adapter.setEntries(newEntries);

		defaultAddrSpace = addrFactory.getDefaultAddressSpace();
		baseAddrs = adapter.getBaseAddresses(true);
		init(true);
	}

	@Override
	public synchronized void renameOverlaySpace(String oldName, String newName) throws IOException {
		adapter.renameOverlaySpace(oldName, newName);
		invalidateCache();
	}

	@Override
	public synchronized void deleteOverlaySpace(String name) throws IOException {
		adapter.deleteOverlaySpace(name);
		invalidateCache();
	}
}
