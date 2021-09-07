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
package ghidra.program.database.register;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.DefaultProgramContext;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.RangeMapAdapter;
import ghidra.program.util.RegisterValueStore;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>ProgramContextDB</code> defines a processor context over an address 
 * space using database range maps for storage.
 */
public class OldProgramContextDB implements ProgramContext, DefaultProgramContext, ManagerDB {

	private final static UndefinedValueException UNDEFINED_VALUE_EXCEPTION =
		new UndefinedValueException();

	private final static String OLD_CONTEXT_TABLE_PREFIX =
		AddressRangeMapDB.RANGE_MAP_TABLE_PREFIX + "ProgContext";

	private DBHandle dbHandle;
	private ErrorHandler errHandler;
	private Language language;
	private AddressMap addrMap;
	private Lock lock;

	/**
	 * maintain values stored in registers for specified addresses and
	 * address ranges using the PropertyMap utilities.
	 */
	private Map<Integer, AddressRangeMapDB> valueMaps;
	private Register baseContextRegister;
	protected Map<Register, RegisterValueStore> defaultRegisterValueMap;

	private Register[] registersWithValues;

	private RegisterValue defaultDisassemblyContext;

	/**
	 * Constructs a new ProgramContextDB object
	 * @param dbHandle the handle to the database.
	 * @param errHandler the error handler
	 * @param language the processor language
	 * @param addrMap the address map.
	 * @param lock the program synchronization lock
	 */
	public OldProgramContextDB(DBHandle dbHandle, ErrorHandler errHandler, Language language,
			AddressMap addrMap, Lock lock) {

		this.dbHandle = dbHandle;
		this.errHandler = errHandler;
		this.lock = lock;
		this.addrMap = addrMap.getOldAddressMap();
		this.language = language;

		defaultRegisterValueMap = new HashMap<Register, RegisterValueStore>();
		valueMaps = new HashMap<>();

		baseContextRegister = language.getContextBaseRegister();
		defaultDisassemblyContext = new RegisterValue(baseContextRegister);

		initializeDefaultValues(language);
	}

	static boolean oldContextDataExists(DBHandle dbh) {
		for (Table table : dbh.getTables()) {
			if (table.getName().startsWith(OLD_CONTEXT_TABLE_PREFIX)) {
				return true;
			}
		}
		return false;
	}

	static void removeOldContextData(DBHandle dbh) throws IOException {
		for (Table table : dbh.getTables()) {
			if (table.getName().startsWith(OLD_CONTEXT_TABLE_PREFIX)) {
				dbh.deleteTable(table.getName());
			}
		}
	}

	private void initializeDefaultValues(Language lang) {
		if (lang != null) {
			lang.applyContextSettings(this);
		}
	}

	@Override
	public void deleteAddressRange(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {
		throw new UnsupportedOperationException();
	}

	public long get(Address addr, Register reg) {
		throw new UnsupportedOperationException();
	}

	@Override
	public Register getBaseContextRegister() {
		return baseContextRegister;
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register) {
		RegisterValueStore store = defaultRegisterValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return store.getAddressRangeIterator();
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
			Address start, Address end) {
		RegisterValueStore store = defaultRegisterValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return store.getAddressRangeIterator(start, end);
	}

	@Override
	public RegisterValue getDefaultValue(Register register, Address address) {
		RegisterValueStore store = defaultRegisterValueMap.get(register.getBaseRegister());
		if (store == null) {
			return null;
		}
		return store.getValue(register, address);
	}

	@Override
	public RegisterValue getNonDefaultValue(Register register, Address address) {
		return getRegisterValue(register, address);
	}

	@Override
	public List<Register> getContextRegisters() {
		return language.getContextRegisters();
	}

	@Override
	public Register getRegister(String name) {
		return language.getRegister(name);
	}

	@Override
	public List<String> getRegisterNames() {
		return language.getRegisterNames();
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register) {
		AddressSet set = addrMap.getAddressFactory().getAddressSet();
		return getRegisterValueAddressRanges(register, set.getMinAddress(), set.getMaxAddress());
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
			Address end) {
		RegisterValueRange[] valueRanges = getRegisterValues(register, start, end);
		return new SimpleAddressRangeIterator(valueRanges);
	}

	int getRegisterOffset(Register reg) {
		int offset = reg.getOffset();

		if (reg.getBitLength() == 1 && !reg.isProcessorContext()) {
			offset |= ((reg.getLeastSignificantBit()) << 28);
			offset |= 0x90000000;
		}
		return offset;
	}

	public RegisterValueRange[] getRegisterValues(Register reg, Address start, Address end) {

		SortedSet<Address> changePoints =
			getChangePoints(start, end, getRegisterOffset(reg), reg.getMinimumByteSize());

		ArrayList<RegisterValueRange> ranges = new ArrayList<RegisterValueRange>();

		Iterator<Address> it = changePoints.iterator();
		Address currentAddress = start;
		while (it.hasNext()) {
			Address nextChange = it.next();
			addRange(reg, ranges, currentAddress, nextChange.previous());
			currentAddress = nextChange;
		}
		addRange(reg, ranges, currentAddress, end);

		RegisterValueRange[] rangeArray = new RegisterValueRange[ranges.size()];
		ranges.toArray(rangeArray);
		return rangeArray;
	}

	private void addRange(Register reg, ArrayList<RegisterValueRange> ranges, Address start,
			Address end) {
		if (end == null) {
			addRange(reg, ranges, start, start.getAddressSpace().getMaxAddress());
		}
		else if (!start.getAddressSpace().equals(end.getAddressSpace())) {
			addRange(reg, ranges, start, start.getAddressSpace().getMaxAddress());
			addRange(reg, ranges, end.getAddressSpace().getMinAddress(), end);
			return;
		}
		else {
			RegisterValueRange valueRange = getRegisterRange(reg, start, end);
			if (valueRange.getValue() != null) {
				ranges.add(valueRange);
			}
		}
	}

	@Override
	public List<Register> getRegisters() {
		return language.getRegisters();
	}

	public long getSigned(Address addr, Register reg) throws UnsupportedOperationException {
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getRegisterValue(Register register, Address address) {
		Register baseReg = register.getBaseRegister();
		int size = baseReg.getMinimumByteSize();
		int offset = getRegisterOffset(register);
		byte[] bytes = new byte[2 * size];
		for (int i = 0; i < size; i++) {
			int index = register.isBigEndian() ? i : (size - i - 1);
			bytes[i] = 0x00;
			try {
				bytes[size + index] = getByte(offset + i, address);
				bytes[index] = (byte) 0xff;
			}
			catch (UndefinedValueException e) {
				// ignore byte
			}
		}
		return new RegisterValue(register, bytes);
	}

	@Override
	public BigInteger getValue(Register register, Address address, boolean signed) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasValueOverRange(Register reg, BigInteger value, AddressSetView addrSet) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void remove(Address start, Address end, Register register) {
		throw new UnsupportedOperationException();
	}

	public void set(Address start, Address end, Register reg, long value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
		Register baseRegister = registerValue.getRegister().getBaseRegister();
		RegisterValueStore store = defaultRegisterValueMap.get(baseRegister);
		if (store == null) {
			RangeMapAdapter adapter = new InMemoryRangeMapAdapter();
			store = new RegisterValueStore(registerValue.getRegister().getBaseRegister(), adapter,
				false);
			defaultRegisterValueMap.put(baseRegister, store);
		}
		store.setValue(start, end, registerValue);
	}

	@Override
	public void setValue(Register register, Address start, Address end, BigInteger value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void setRegisterValue(Address start, Address end, RegisterValue value) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		lock.acquire();
		try {
			valueMaps.clear();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
	}

	@Override
	public void setProgram(ProgramDB program) {
	}

	@Override
	public RegisterValue getDefaultDisassemblyContext() {
		return defaultDisassemblyContext;
	}

	@Override
	public void setDefaultDisassemblyContext(RegisterValue newContext) {
		defaultDisassemblyContext = newContext;
	}

	private byte getByte(int offset, Address addr) throws UndefinedValueException {
		AddressRangeMapDB map = getRangeMap(offset);
		if (map != null) {
			Field value = map.getValue(addr);
			if (value != null) {
				return value.getByteValue();
			}
		}
		throw UNDEFINED_VALUE_EXCEPTION;
	}

	private AddressRangeMapDB getRangeMap(int offset) {
		AddressRangeMapDB map = valueMaps.get(offset);
		if (map == null) {
			map = createMap(offset);
		}
		return map;
	}

	private AddressRangeMapDB createMap(int offset) {
		lock.acquire();
		try {
			AddressRangeMapDB map = new AddressRangeMapDB(dbHandle, addrMap, lock,
				"ProgContext" + offset, errHandler, ByteField.INSTANCE, false);
			valueMaps.put(offset, map);
			return map;
		}
		finally {
			lock.release();
		}
	}

	private SortedSet<Address> getChangePoints(Address startAddr, Address endAddr,
			int registerOffset, int registerLength) {

		SortedSet<Address> changePoints = new TreeSet<Address>();

		AddressRangeMapDB map = getRangeMap(registerOffset);
		if (map != null) {
			AddressRangeIterator iter = map.getAddressRanges(startAddr, endAddr);
			Address curr = startAddr;
			while (iter.hasNext() && curr.compareTo(endAddr) < 0) {
				AddressRange range = iter.next();
				Address rangeStart = range.getMinAddress();
				if (!rangeStart.equals(curr)) {
					changePoints.add(rangeStart);
				}
				Address rangeEnd = range.getMaxAddress();
				curr = rangeEnd.addWrap(1);
				if (curr.compareTo(endAddr) <= 0) {
					changePoints.add(curr);
				}
			}
		}

		return changePoints;
	}

	private RegisterValueRange getRegisterRange(Register register, Address start, Address end) {
		return new RegisterValueRange(start, end, getRegisterValue(register, start));
	}

	@Override
	public Register[] getRegistersWithValues() {
		if (registersWithValues == null) {
			List<Register> tmp = new ArrayList<Register>();
			for (Register register : getRegisters()) {
				AddressRangeIterator it = getRegisterValueAddressRanges(register);
				if (it.hasNext()) {
					tmp.add(register);
					continue;
				}
				it = getDefaultRegisterValueAddressRanges(register);
				if (it.hasNext()) {
					tmp.add(register);
				}
			}
			registersWithValues = tmp.toArray(new Register[tmp.size()]);
		}
		return registersWithValues;
	}

	@Override
	public RegisterValue getDisassemblyContext(Address address) {
		return getDefaultDisassemblyContext();
	}

	@Override
	public AddressRange getRegisterValueRangeContaining(Register register, Address addr) {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNonFlowingContext() {
		// Only used during disassembly which is not supported
		// for this read-only context
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getFlowValue(RegisterValue value) {
		// Only used during disassembly which is not supported
		// for this read-only context
		throw new UnsupportedOperationException();
	}

	@Override
	public RegisterValue getNonFlowValue(RegisterValue value) {
		// Only used during disassembly which is not supported
		// for this read-only context
		throw new UnsupportedOperationException();
	}

}

class SimpleAddressRangeIterator implements AddressRangeIterator {
	int pos = 0;
	RegisterValueRange[] valueRanges;

	public SimpleAddressRangeIterator(RegisterValueRange[] valueRanges) {
		this.valueRanges = valueRanges == null ? new RegisterValueRange[0] : valueRanges;
	}

	@Override
	public Iterator<AddressRange> iterator() {
		return this;
	}

	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean hasNext() {
		return pos < valueRanges.length;
	}

	@Override
	public AddressRange next() {
		RegisterValueRange valueRange = valueRanges[pos++];
		return new AddressRangeImpl(valueRange.getStartAddress(), valueRange.getEndAddress());
	}

}

/**
 * Represents a register value over a range of addresses.
 */
class RegisterValueRange {
	private Address startAddr;
	private Address endAddr;
	private RegisterValue value;

	/**
	 * Constructor for RegisterValueRange.
	 * @param startAddr the first address in the range
	 * @param endAddr the last address in the range
	 * @param value the value of the register over the range.
	 */
	public RegisterValueRange(Address startAddr, Address endAddr, RegisterValue value) {
		this.startAddr = startAddr;
		this.endAddr = endAddr;
		this.value = value;
	}

	/**
	 * Get the start address of the range.
	 */
	public Address getStartAddress() {
		return startAddr;
	}

	/**
	 * Set the end address of the range.
	 * @param addr the new start address.
	 */
	public void setStartAddress(Address addr) {
		startAddr = addr;
	}

	/**
	 * Get the end address of the range.
	 */
	public Address getEndAddress() {
		return endAddr;
	}

	/**
	 * Set the end address of the range.
	 * @param addr the new end address.
	 */
	public void setEndAddress(Address addr) {
		endAddr = addr;
	}

	/**
	 * Get the register value.
	 */
	public RegisterValue getValue() {
		return value;
	}

}
