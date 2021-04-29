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
package ghidra.trace.database.program;

import java.math.BigInteger;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;

import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.util.AbstractProgramContext;
import ghidra.trace.database.context.DBTraceRegisterContextManager;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.LockHold;

public class DBTraceProgramViewProgramContext extends AbstractProgramContext {

	private final DBTraceProgramView program;

	private final Language language;
	private final DBTraceRegisterContextManager registerContextManager;
	private final ProgramContext defaultContext;

	public DBTraceProgramViewProgramContext(DBTraceProgramView program) {
		super(program.language);
		this.program = program;
		this.language = program.language;
		this.registerContextManager = program.trace.getRegisterContextManager();
		this.defaultContext = registerContextManager.getDefaultContext(language);
	}

	@Override
	public Register[] getRegistersWithValues() {
		List<Register> registers = language.getRegisters();
		List<Register> result = new ArrayList<>(registers.size());
		for (Register register : registers) {
			for (long s : program.viewport.getReversedSnaps()) {
				if (registerContextManager.hasRegisterValue(language, register, s)) {
					result.add(register);
					break;
				}
			}
		}
		return result.toArray(new Register[result.size()]);
	}

	@Override
	public BigInteger getValue(Register register, Address address, boolean signed) {
		RegisterValue value = getRegisterValue(register, address);
		return value == null ? null : signed ? value.getSignedValue() : value.getUnsignedValue();
	}

	protected RegisterValue combine(RegisterValue v1, RegisterValue v2) {
		if (v1 == null) {
			return v2;
		}
		else if (v2 == null) {
			return v1;
		}
		return v1.combineValues(v2);
	}

	protected RegisterValue stack(RegisterValue value, Register register, Address address) {
		for (long s : program.viewport.getReversedSnaps()) {
			value = combine(value, registerContextManager.getValue(language, register, s, address));
		}
		return value;
	}

	@Override
	public RegisterValue getRegisterValue(Register register, Address address) {
		RegisterValue value = registerContextManager.getDefaultValue(language, register, address);
		return stack(value, register, address);
	}

	@Override
	public void setRegisterValue(Address start, Address end, RegisterValue value)
			throws ContextChangeException {
		registerContextManager.setValue(language, value, Range.atLeast(program.snap),
			new AddressRangeImpl(start, end));
	}

	@Override
	public RegisterValue getNonDefaultValue(Register register, Address address) {
		RegisterValue value = new RegisterValue(register);
		return stack(value, register, address);
	}

	@Override
	public void setValue(Register register, Address start, Address end, BigInteger value)
			throws ContextChangeException {
		setRegisterValue(start, end, new RegisterValue(register, value));
	}

	private static class NestedAddressRangeIterator<U> extends NestedIterator<U, AddressRange>
			implements AddressRangeIterator {
		protected NestedAddressRangeIterator(Iterator<U> it,
				Function<U, Iterator<? extends AddressRange>> f) {
			super(it, f);
		}

		@Override
		public Iterator<AddressRange> iterator() {
			return this;
		}
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register) {
		return program.viewport.unionedAddresses(
			s -> registerContextManager.getRegisterValueAddressRanges(language, register,
				s)).getAddressRanges();
	}

	@Override
	public AddressRangeIterator getRegisterValueAddressRanges(Register register, Address start,
			Address end) {
		return new NestedAddressRangeIterator<>(
			language.getAddressFactory().getAddressSet(start, end).iterator(),
			range -> program.viewport.unionedAddresses(
				s -> registerContextManager.getRegisterValueAddressRanges(language, register,
					s, range)).iterator());
	}

	@Override
	public AddressRange getRegisterValueRangeContaining(Register register, Address address) {
		// TODO: I don't know the value of making this work through the viewport.
		Entry<TraceAddressSnapRange, RegisterValue> entry =
			registerContextManager.getEntry(language, register, program.snap, address);
		if (entry != null) {
			return entry.getKey().getRange();
		}

		// Compute the gap
		AddressSetView ranges =
			registerContextManager.getRegisterValueAddressRanges(language, register, program.snap);
		Iterator<Address> prevIt = ranges.getAddresses(address, false);
		Address min =
			prevIt.hasNext() ? prevIt.next().next() : address.getAddressSpace().getMinAddress();
		Iterator<Address> nextIt = ranges.getAddresses(address, true);
		Address max =
			nextIt.hasNext() ? nextIt.next().previous() : address.getAddressSpace().getMaxAddress();
		return new AddressRangeImpl(min, max);
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register) {
		return defaultContext.getDefaultRegisterValueAddressRanges(register);
	}

	@Override
	public AddressRangeIterator getDefaultRegisterValueAddressRanges(Register register,
			Address start, Address end) {
		return defaultContext.getDefaultRegisterValueAddressRanges(register, start, end);
	}

	@Override
	public void remove(Address start, Address end, Register register)
			throws ContextChangeException {
		try (LockHold hold = program.trace.lockWrite()) {
			Range<Long> span = Range.closed(program.snap, program.snap);
			for (AddressRange range : language.getAddressFactory().getAddressSet(start, end)) {
				registerContextManager.removeValue(language, register, span, range);
			}
		}
	}

	@Override
	public boolean hasValueOverRange(Register register, BigInteger value,
			AddressSetView addressSet) {
		// TODO: Not sure the value of making this use the viewport
		RegisterValue regVal = new RegisterValue(register, value);
		try (LockHold hold = program.trace.lockRead()) {
			AddressSet remains = new AddressSet(addressSet);
			while (!remains.isEmpty()) {
				AddressSet toRemove = new AddressSet();
				for (AddressRange range : remains) {
					Entry<TraceAddressSnapRange, RegisterValue> entry =
						registerContextManager.getEntry(language, register, program.snap,
							range.getMinAddress());
					if (entry == null) {
						return false;
					}
					if (!regVal.equals(entry.getValue())) {
						return false;
					}
					toRemove.add(entry.getKey().getRange());
				}
				remains.delete(toRemove);
			}
			return true;
		}
	}

	@Override
	public RegisterValue getDefaultValue(Register register, Address address) {
		return defaultContext.getDefaultValue(register, address);
	}

	@Override
	public RegisterValue getDisassemblyContext(Address address) {
		RegisterValue value = getRegisterValue(baseContextRegister, address);
		if (value != null) {
			return value;
		}
		return defaultContext.getDisassemblyContext(address);
	}

	@Override
	public void setDefaultValue(RegisterValue registerValue, Address start, Address end) {
		throw new UnsupportedOperationException();
	}
}
