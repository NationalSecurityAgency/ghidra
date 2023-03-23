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
package ghidra.app.plugin.core.debug.stack;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.app.plugin.core.debug.stack.Sym.RegisterSym;
import ghidra.app.plugin.core.debug.stack.Sym.StackDerefSym;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.trace.database.DBTraceUtils.AddressRangeMapSetter;
import ghidra.util.Msg;

/**
 * The portion of a {@link SymPcodeExecutorState} associated with a specific {@link AddressSpace}.
 */
public class SymStateSpace {

	/**
	 * A symbolic entry in the state
	 * 
	 * <p>
	 * It's possible the entry becomes truncated if another entry set later would overlap. Thus, it
	 * is necessary to remember the original range and the effective range as well as the symbol.
	 */
	record SymEntry(AddressRange entRange, AddressRange symRange, Sym sym) {
		/**
		 * Create a new entry for the given range and symbol
		 * 
		 * @param range the range
		 * @param sym the symbol
		 */
		SymEntry(AddressRange range, Sym sym) {
			this(range, range, sym);
		}

		/**
		 * Create a new entry for the given range and symbol
		 * 
		 * @param start the min address of the range
		 * @param size the size in bytes of the range
		 * @param sym the symbol
		 * @throws AddressOverflowException
		 */
		SymEntry(Address start, int size, Sym sym) throws AddressOverflowException {
			this(new AddressRangeImpl(start, size), sym);
		}

		/**
		 * Render a human-friendly string, substituting register names for ranges where appropriate
		 * 
		 * @param language optional language. If omitted, no register names are substituted
		 * @return the string
		 */
		public String toString(Language language) {
			Register reg = getRegister(language);
			if (reg == null) {
				return toString();
			}
			return String.format("%s[entRanage=%s,symRange=%s,sym=%s]", getClass().getSimpleName(),
				reg, symRange, sym);
		}

		/**
		 * Check if this entry has been truncated
		 * 
		 * @return true if the effective range is equal to the original range
		 */
		boolean isTruncated() {
			return !entRange.equals(symRange);
		}

		/**
		 * Get the register in the language this entry's range represents
		 * 
		 * @param language the language
		 * @return the register, or null
		 */
		Register getRegister(Language language) {
			return language.getRegister(entRange.getMinAddress(), (int) entRange.getLength());
		}

		/**
		 * Create a new entry that represents a truncation of this entry
		 * 
		 * @param range the subrange
		 * @return the new entry
		 */
		SymEntry truncate(AddressRange range) {
			if (entRange.getMinAddress().compareTo(range.getMinAddress()) > 0) {
				throw new AssertionError();
			}
			if (entRange.getMaxAddress().compareTo(range.getMaxAddress()) < 0) {
				throw new AssertionError();
			}
			return new SymEntry(range, symRange, sym);
		}

		/**
		 * Check if the effective range contains the given address
		 * 
		 * @param address the address
		 * @return true if contained by this entry
		 */
		boolean contains(Address address) {
			return entRange.contains(address);
		}

		/**
		 * Get the symbol from this entry, applying appropriate arithmetic for truncation, if
		 * applicable.
		 * 
		 * @param range the range to extract
		 * @param arithmetic the arithmetic for extracting the appropriate bytes
		 * @return the symbol
		 */
		Sym extract(AddressRange range, SymPcodeArithmetic arithmetic) {
			if (symRange.equals(range)) {
				return sym;
			}
			// TODO: Implement the extraction logic. Not sure it matters, anyway
			return Sym.opaque();
			/* long shift = arithmetic.getEndian().isBigEndian()
					? symRange.getMaxAddress().subtract(range.getMaxAddress())
					: range.getMinAddress().subtract(symRange.getMinAddress()); */
		}
	}

	/**
	 * A setter that knows how to remove or truncate overlapping entries
	 */
	protected class ExprMapSetter
			extends AddressRangeMapSetter<Map.Entry<Address, SymEntry>, SymEntry> {
		@Override
		protected AddressRange getRange(Entry<Address, SymEntry> entry) {
			return entry.getValue().entRange;
		}

		@Override
		protected SymEntry getValue(Entry<Address, SymEntry> entry) {
			return entry.getValue();
		}

		@Override
		protected void remove(Entry<Address, SymEntry> entry) {
			map.remove(entry.getKey());
		}

		@Override
		protected Iterable<Entry<Address, SymEntry>> getIntersecting(Address lower,
				Address upper) {
			return subMap(lower, upper).entrySet();
		}

		@Override
		protected Entry<Address, SymEntry> put(AddressRange range, SymEntry value) {
			map.put(range.getMinAddress(), value.truncate(range));
			return null;
		}
	}

	final NavigableMap<Address, SymEntry> map;
	private final ExprMapSetter setter = new ExprMapSetter();

	/**
	 * Construct a new empty space
	 */
	public SymStateSpace() {
		this.map = new TreeMap<>();
	}

	/**
	 * Construct a space with the given map (for forking)
	 * 
	 * @param map the map
	 */
	protected SymStateSpace(NavigableMap<Address, SymEntry> map) {
		this.map = map;
	}

	@Override
	public String toString() {
		return toString("", null);
	}

	/**
	 * Render a human-friendly string showing this state space
	 * 
	 * @param indent the indentation
	 * @param language the language, optional, for register substitution
	 * @return the string
	 */
	public String toString(String indent, Language language) {
		return map.values()
				.stream()
				.map(se -> se.toString(language))
				.collect(Collectors.joining("\n" + indent, indent + "{", "\n" + indent + "}"));
	}

	private NavigableMap<Address, SymEntry> subMap(Address lower, Address upper) {
		Entry<Address, SymEntry> adjEnt = map.floorEntry(lower);
		if (adjEnt != null && adjEnt.getValue().contains(upper)) {
			lower = adjEnt.getKey();
		}
		return map.subMap(lower, true, upper, true);
	}

	/**
	 * Set a value in this space
	 * 
	 * @param address the address of the entry
	 * @param size the size of the entry
	 * @param sym the symbol
	 */
	public void set(Address address, int size, Sym sym) {
		SymEntry entry;
		try {
			entry = new SymEntry(address, size, sym);
		}
		catch (AddressOverflowException e) {
			throw new AssertionError(e);
		}
		setter.set(entry.entRange, entry);
	}

	/**
	 * Get a value from this space
	 * 
	 * @param address the address of the value
	 * @param size the size of the value
	 * @param arithmetic the arithmetic, in case truncation is necessary
	 * @param language the language, for generating symbols
	 * @return the symbol
	 */
	public Sym get(Address address, int size, SymPcodeArithmetic arithmetic, Language language) {
		AddressRange range;
		range = new AddressRangeImpl(address, address.add(size - 1));
		Sym result = null;
		Address expectedNext = null;
		for (SymEntry ent : subMap(range.getMinAddress(), range.getMaxAddress()).values()) {
			if (ent.entRange.equals(range)) {
				return ent.extract(range, arithmetic);
			}
			AddressRange intersection = range.intersect(ent.entRange);
			if (expectedNext != null && !expectedNext.equals(intersection.getMinAddress())) {
				return Sym.opaque();
			}
			expectedNext = intersection.getMaxAddress().next();
			Sym piece = ent.extract(intersection, arithmetic);
			piece =
				arithmetic.unaryOp(PcodeOp.INT_ZEXT, size, (int) intersection.getLength(), piece);
			if (result == null) {
				result = piece;
				continue;
			}
			result = arithmetic.binaryOp(PcodeOp.INT_OR, size, size, piece, size, result);
		}
		if (result != null) {
			return result;
		}
		if (address.isRegisterAddress()) {
			Register register = language.getRegister(address, size);
			if (register == null) {
				Msg.warn(this, "Could not figure register: address=" + address + ",size=" + size);
				return Sym.opaque();
			}
			return new RegisterSym(register);
		}
		if (address.isStackAddress()) {
			return new StackDerefSym(address.getOffset(), size);
		}
		return Sym.opaque();
	}

	/**
	 * Reset this state
	 * 
	 * <p>
	 * Clears the state as if it were new. That is, it will generate fresh symbols for reads without
	 * existing entries.
	 */
	public void clear() {
		map.clear();
	}

	public void dump(String prefix, Language language) {
		for (SymEntry ent : map.values()) {
			Register register = ent.getRegister(language);
			if (register != null) {
				System.err.println(prefix + register + " = " + ent.sym);
				continue;
			}
			System.err.println(prefix + ent);
		}
	}

	/**
	 * Copy this state
	 * 
	 * @return the new state
	 */
	public SymStateSpace fork() {
		return new SymStateSpace(new TreeMap<>(map));
	}
}
