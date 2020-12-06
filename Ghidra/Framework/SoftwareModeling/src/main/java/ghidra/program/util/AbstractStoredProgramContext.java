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
package ghidra.program.util;

import java.math.BigInteger;
import java.util.*;

import ghidra.program.database.register.InMemoryRangeMapAdapter;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

abstract public class AbstractStoredProgramContext extends AbstractProgramContext {

	protected Map<Register, RegisterValueStore> registerValueMap;
	protected Map<Register, RegisterValueStore> defaultRegisterValueMap;

	private Set<Register> registersWithValues; // cached set, recomputed whenever null

	protected AbstractStoredProgramContext(Language language) {
		super(language);
		registerValueMap = new HashMap<>();
		defaultRegisterValueMap = new HashMap<>();
	}

	/**
	 * Flush any cached context not yet written to database
	 */
	public void flushProcessorContextWriteCache() {
		RegisterValueStore store = registerValueMap.get(baseContextRegister);
		if (store != null) {
			store.flushWriteCache();
		}
	}

	/**
	 * Flush any cached context not yet written to database
	 */
	public void invalidateProcessorContextWriteCache() {
		RegisterValueStore store = registerValueMap.get(baseContextRegister);
		if (store != null) {
			store.invalidateWriteCache();
		}
	}

	protected void moveAddressRange(Address fromAddr, Address toAddr, long length,
			TaskMonitor monitor) throws CancelledException {
		for (RegisterValueStore store : registerValueMap.values()) {
			store.moveAddressRange(fromAddr, toAddr, length, monitor);
		}
	}

	protected final RegisterValueStore createRegisterValueStore(Register baseRegister,
			RangeMapAdapter adapter) {
		RegisterValueStore store =
			new RegisterValueStore(baseRegister, adapter, baseRegister.isProcessorContext());
		registerValueMap.put(baseRegister, store);
		return store;
	}

	@Override
	public void setRegisterValue(Address start, Address end, RegisterValue value)
			throws ContextChangeException {
		if (value == null) {
			throw new IllegalArgumentException("Value cannot be null, use remove() instead!");
		}
		Register baseRegister = value.getRegister().getBaseRegister();
		RegisterValueStore store = registerValueMap.get(baseRegister);
		if (store == null) {
			RangeMapAdapter adapter = createNewRangeMapAdapter(baseRegister);
			store = createRegisterValueStore(baseRegister, adapter);
		}
		store.setValue(start, end, value);
		if (registersWithValues != null && !registersWithValues.contains(baseRegister)) {
			addRegisterWithValue(baseRegister);
		}
	}

	private void addRegisterWithValue(Register reg) {
		registersWithValues.add(reg);
		for (Register child : reg.getChildRegisters()) {
			addRegisterWithValue(child);
		}
	}

	@Override
	public RegisterValue getRegisterValue(Register register, Address address) {
		RegisterValue registerValue = getRegisterValue(register, address, registerValueMap);

		if (registerValue != null && registerValue.hasValue()) {
			return registerValue;
		}

		RegisterValue defaultRegisterValue =
			getRegisterValue(register, address, defaultRegisterValueMap);
		if (defaultRegisterValue != null) {
			return defaultRegisterValue.combineValues(registerValue);
		}
		return registerValue;
	}

	@Override
	public BigInteger getValue(Register register, Address address, boolean signed) {
		RegisterValue registerValue = getRegisterValue(register, address);
		if (registerValue != null) {
			return signed ? registerValue.getSignedValue() : registerValue.getUnsignedValue();
		}
		return null;
	}

	protected void deleteAddressRange(Address start, Address end, TaskMonitor monitor) {
		for (RegisterValueStore registerValueStore : registerValueMap.values()) {
			registerValueStore.clearValue(start, end, null);
		}
		invalidateReadCache();
	}

	private RegisterValue getRegisterValue(Register register, Address address,
			Map<Register, RegisterValueStore> map) {

		/** if the address is in an overlay and we are getting the default value, then get the default
		 * value from the base space, not the overlay space.
		 */
		if (map == defaultRegisterValueMap && address.getAddressSpace().isOverlaySpace()) {
			address =
				((OverlayAddressSpace) address.getAddressSpace()).translateAddress(address, true);
		}

		RegisterValueStore store = map.get(register.getBaseRegister());
		if (store == null) {
			return null;
		}

		return store.getValue(register, address);
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register) {
		RegisterValueStore store = registerValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return new RegisterAddressRangeIterator(register, store.getAddressRangeIterator(),
			registerValueMap);
	}

	@Override
	public AddressRange getRegisterValueRangeContaining(Register register, Address addr) {
		RegisterValueStore store = registerValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressRangeImpl(addr, addr);
		}
		return store.getValueRangeContaining(addr);
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
			Address end) {
		RegisterValueStore store = registerValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return new RegisterAddressRangeIterator(register, store.getAddressRangeIterator(start, end),
			registerValueMap);
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register) {
		RegisterValueStore store = defaultRegisterValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return new RegisterAddressRangeIterator(register, store.getAddressRangeIterator(),
			defaultRegisterValueMap);
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
			Address start, Address end) {
		RegisterValueStore store = defaultRegisterValueMap.get(register.getBaseRegister());
		if (store == null) {
			return new AddressSet().getAddressRanges();
		}
		return new RegisterAddressRangeIterator(register, store.getAddressRangeIterator(start, end),
			defaultRegisterValueMap);
	}

	@Override
	public Register[] getRegistersWithValues() {
		if (registersWithValues == null) {
			registersWithValues = new HashSet<>();
			for (Register register : language.getRegisters()) {
				RegisterValueStore store = registerValueMap.get(register.getBaseRegister());
				if (store != null && !store.isEmpty()) {
					registersWithValues.add(register);
					continue;
				}
				store = defaultRegisterValueMap.get(register.getBaseRegister());
				if (store != null && !store.isEmpty()) {
					registersWithValues.add(register);
				}
			}
		}
		Register[] regs = new Register[registersWithValues.size()];
		return registersWithValues.toArray(regs);
	}

	@Override
	public boolean hasValueOverRange(Register reg, BigInteger value, AddressSetView addrSet) {
		AddressRangeIterator it = addrSet.getAddressRanges();
		while (it.hasNext()) {
			AddressRange range = it.next();
			if (!hasValueOverRange(reg, value, range.getMinAddress(), range.getMaxAddress())) {
				return false;
			}
		}
		return true;
	}

	private boolean hasValueOverRange(Register reg, BigInteger value, Address start, Address end) {
		AddressRangeIterator it = getRegisterValueAddressRanges(reg, start, end);
		if (it.hasNext()) {
			AddressRange range = it.next();
			if (range.getMinAddress().equals(start) && range.getMaxAddress().equals(end)) {
				BigInteger regValue = getValue(reg, start, true);
				return value.equals(regValue);
			}
		}
		return false;
	}

	@Override
	public void remove(Address start, Address end, Register register)
			throws ContextChangeException {
		if (start.getAddressSpace() != end.getAddressSpace()) {
			throw new AssertException("start and end address must be in the same address space");
		}
		RegisterValueStore values = registerValueMap.get(register.getBaseRegister());
		if (values != null) {
			values.clearValue(start, end, register);
		}
		invalidateReadCache();
	}

//	public void removeDefault(Address start, Address end, Register register) {
//		if (start.getAddressSpace() != end.getAddressSpace()) {
//			throw new AssertException("start and end address must be in the same address space");
//		}
//		invalidateCache();
//		RegisterValueStore values = defaultRegisterValueMap.get(register.getBaseRegister());
//		if (values != null) {
//			values.clearValue(start, end, register);
//		}
//	}

	@Override
	public void setValue(Register register, Address start, Address end, BigInteger value)
			throws ContextChangeException {
		if (start.getAddressSpace() != end.getAddressSpace()) {
			throw new AssertException("start and end address must be in the same address space");
		}
		if (value == null) {
			remove(start, end, register);
			return;
		}
		setRegisterValue(start, end, new RegisterValue(register, value));
	}

	@Override
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
		if (start.getAddressSpace() != end.getAddressSpace()) {
			throw new AssertException("start and end address must be in the same address space");
		}
		Register baseRegister = registerValue.getRegister().getBaseRegister();
		RegisterValueStore store = defaultRegisterValueMap.get(baseRegister);
		if (store == null) {
			RangeMapAdapter adapter = new InMemoryRangeMapAdapter();
			store = new RegisterValueStore(baseRegister, adapter, false);
			defaultRegisterValueMap.put(baseRegister, store);
		}
		store.setValue(start, end, registerValue);
		invalidateReadCache();
	}

	@Override
	public RegisterValue getDefaultValue(Register register, Address address) {
		AddressSpace space = address.getAddressSpace();

		// if the address is in an overlay then the default value comes from the original space.
		if (space.isOverlaySpace()) {
			address = ((OverlayAddressSpace) space).translateAddress(address, true);
		}
		// there is a weird deleted overlay case that the following code handles - sortof
		else if (space.getType() == AddressSpace.TYPE_UNKNOWN) {
			return new RegisterValue(register);
		}
		return getRegisterValue(register, address, defaultRegisterValueMap);
	}

	@Override
	public RegisterValue getNonDefaultValue(Register register, Address address) {
		return getRegisterValue(register, address, registerValueMap);
	}

	abstract protected RangeMapAdapter createNewRangeMapAdapter(Register baseRegister);

	protected void invalidateReadCache() {
		registersWithValues = null;
	}

	protected void invalidateWriteCache() {
		RegisterValueStore store = registerValueMap.get(baseContextRegister);
		if (store != null) {
			store.invalidateWriteCache();
		}
	}

	@Override
	public RegisterValue getDisassemblyContext(Address address) {
		RegisterValue defaultValue =
			getRegisterValue(baseContextRegister, address, defaultRegisterValueMap);
		RegisterValue currentValue =
			getRegisterValue(baseContextRegister, address, registerValueMap);
		if (defaultValue == null) {
			defaultValue = defaultDisassemblyContext;
		}
		else {
			defaultValue = defaultValue.combineValues(defaultDisassemblyContext);
		}
		return defaultValue.combineValues(currentValue);
	}

	class RegisterAddressRangeIterator implements AddressRangeIterator {
		private Register register;
		private AddressRangeIterator it;
		private AddressRange nextRange;
		private Map<Register, RegisterValueStore> map;

		RegisterAddressRangeIterator(Register register, AddressRangeIterator it,
				Map<Register, RegisterValueStore> map) {
			this.register = register;
			this.it = it;
			this.map = map;
			findNextRange();
		}

		private void findNextRange() {
			while (it.hasNext()) {
				nextRange = it.next();
				RegisterValue bytes = getRegisterValue(register, nextRange.getMinAddress(), map);
				if (bytes != null && bytes.hasAnyValue()) {
					return;
				}
			}
			nextRange = null;
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
			return nextRange != null;
		}

		@Override
		public AddressRange next() {
			AddressRange retRange = nextRange;
			findNextRange();
			return retRange;
		}
	}
}
