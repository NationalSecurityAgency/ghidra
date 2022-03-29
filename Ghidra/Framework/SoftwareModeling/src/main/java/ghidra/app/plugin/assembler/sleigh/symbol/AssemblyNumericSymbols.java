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
package ghidra.app.plugin.assembler.sleigh.symbol;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * A context to hold various symbols offered to the assembler, usable where numbers are expected.
 */
public final class AssemblyNumericSymbols {
	public static final AssemblyNumericSymbols EMPTY =
		new AssemblyNumericSymbols(Map.of(), Map.of(), Map.of());

	/**
	 * Collect labels derived from memory-mapped registers in a language
	 * 
	 * <p>
	 * TODO: Use of registers should be limited to operands whose size match the register size.
	 * 
	 * @param labels the destination map
	 * @param language the language
	 */
	private static void collectLanguageLabels(Map<String, Address> labels, Language language) {
		for (Register reg : language.getRegisters()) {
			// TODO/HACK: There ought to be a better mechanism describing suitable symbolic
			// substitutions for a given operand.
			if (!reg.getAddressSpace().isRegisterSpace()) {
				labels.put(reg.getName(), reg.getAddress());
			}
		}
	}

	/**
	 * Collect labels from the program's database
	 * 
	 * @param labels the destination map
	 * @param program the source program
	 */
	private static void collectProgramLabels(Map<String, Address> labels, Program program) {
		final SymbolIterator it = program.getSymbolTable().getAllSymbols(false);
		while (it.hasNext()) {
			Symbol sym = it.next();
			if (sym.isExternal()) {
				continue; // skip externals - will generally be referenced indirectly not directly
			}
			SymbolType symbolType = sym.getSymbolType();
			if (symbolType != SymbolType.LABEL && symbolType != SymbolType.FUNCTION) {
				continue;
			}
			labels.put(sym.getName(), sym.getAddress());
		}
	}

	/**
	 * Collect equates from the program's database
	 * 
	 * @param equates the destination map
	 * @param programthe source program
	 */
	private static void collectProgramEquates(Map<String, Long> equates, Program program) {
		final Iterator<Equate> it = program.getEquateTable().getEquates();
		while (it.hasNext()) {
			Equate eq = it.next();
			// Thought is: If that's what the user sees, then that's what the user will type!
			equates.put(eq.getDisplayName(), eq.getValue());
		}
	}

	/**
	 * Get symbols from a language, when no program is available
	 * 
	 * @param language the language
	 * @return the symbols
	 */
	public static AssemblyNumericSymbols fromLanguage(Language language) {
		Map<String, Address> labels = new HashMap<>();
		collectLanguageLabels(labels, language);
		return forMaps(Map.of(), labels);
	}

	/**
	 * Get symbols from a program (and its language)
	 * 
	 * <p>
	 * TODO: It might be nice to cache these and use a listener to keep the maps up to date. Will
	 * depend on interactive performance.
	 * 
	 * @param program the program
	 * @return the symbols
	 */
	public static AssemblyNumericSymbols fromProgram(Program program) {
		Map<String, Long> equates = new HashMap<>();
		Map<String, Address> labels = new HashMap<>();
		collectLanguageLabels(labels, program.getLanguage());
		collectProgramLabels(labels, program);
		collectProgramEquates(equates, program);
		return forMaps(equates, labels);
	}

	/**
	 * Get symbols for the given equate and label maps
	 * 
	 * @param equates the equates
	 * @param labels the labels
	 * @return the symbols
	 */
	public static AssemblyNumericSymbols forMaps(Map<String, Long> equates,
			Map<String, Address> labels) {
		return new AssemblyNumericSymbols(Map.copyOf(equates), Map.copyOf(labels),
			groupBySpace(labels));
	}

	private static Map<AddressSpace, Map<String, Address>> groupBySpace(
			Map<String, Address> labels) {
		return Collections.unmodifiableMap(labels.entrySet()
				.stream()
				.collect(Collectors.groupingBy(ent -> ent.getValue().getAddressSpace(),
					Collectors.toUnmodifiableMap(Entry::getKey, Entry::getValue))));
	}

	private final NavigableSet<String> all = new TreeSet<>();
	public final Map<String, Long> equates;
	public final Map<String, Address> labels;
	public final Map<AddressSpace, Map<String, Address>> labelsBySpace;

	private AssemblyNumericSymbols(Map<String, Long> equates, Map<String, Address> labels,
			Map<AddressSpace, Map<String, Address>> labelsBySpace) {
		this.equates = equates;
		this.labels = labels;
		this.labelsBySpace = labelsBySpace;
		all.addAll(equates.keySet());
		all.addAll(labels.keySet());
	}

	/**
	 * Choose any symbol with the given name
	 * 
	 * <p>
	 * This will check equates first, then labels. If an equate is found, its value is returned. If
	 * a label is found, its addressable word offset is returned.
	 * 
	 * @param name the name
	 * @return the value, or null
	 */
	public Long chooseAny(String name) {
		Long eq = equates.get(name);
		if (eq != null) {
			return eq;
		}
		Address addr = labels.get(name);
		if (addr != null) {
			return addr.getAddressableWordOffset();
		}
		return null;
	}

	/**
	 * Choose a label with the given name in the given space
	 * 
	 * @param name the name
	 * @param space the address space
	 * @return the addressable word offset of the found label, or null
	 */
	public Long chooseBySpace(String name, AddressSpace space) {
		Map<String, Address> forSpace = labelsBySpace.get(space);
		if (forSpace == null) {
			return null;
		}
		Address addr = forSpace.get(name);
		if (addr == null) {
			return null;
		}
		return addr.getAddressableWordOffset();
	}

	/**
	 * Choose a symbol with the given name, using the space as a hint
	 * 
	 * <p>
	 * If a space is not given, or if that space is the constant space, then this will choose from
	 * all symbols, via {@link #chooseAny(String)}. If a space is given, and it is not the constant
	 * space, then this will choose from symbols in the given space, via
	 * {@link #chooseBySpace(String, AddressSpace)}.
	 * 
	 * @param name the name
	 * @param space the address space, or null
	 * @return the equate value, or label addressable word offset, or null
	 */
	public Long choose(String name, AddressSpace space) {
		if (space == null || space.isConstantSpace()) {
			return chooseAny(name);
		}
		return chooseBySpace(name, space);
	}

	private Collection<String> suggestFrom(String got, Collection<String> keys, int max,
			boolean sorted) {
		Set<String> result = new HashSet<>();
		int count = 0;
		for (String label : keys) {
			if (count >= max) {
				break;
			}
			if (label.startsWith(got)) {
				result.add(label);
				count++;
			}
			else if (sorted) {
				break;
			}
		}
		return result;
	}

	/**
	 * Suggest up to max symbols having the given prefix
	 * 
	 * @param got the prefix
	 * @param max the maximum number of symbols to suggest
	 * @return the collection of symbol names
	 */
	public Collection<String> suggestAny(String got, int max) {
		return suggestFrom(got, all.tailSet(got), max, true);
	}

	/**
	 * Suggest up to max symbols from the given space having the given prefix
	 * 
	 * @param got the prefix
	 * @param space the address space
	 * @param max the maximum number of symbols to suggest
	 * @return the collection of symbol names
	 */
	public Collection<String> suggestBySpace(String got, AddressSpace space, int max) {
		Map<String, Address> forSpace = labelsBySpace.get(space);
		if (forSpace == null) {
			return Set.of();
		}
		// TODO: Should I sort these, perhaps lazily, to speed search?
		return suggestFrom(got, forSpace.keySet(), max, false);
	}

	/**
	 * Suggest up to max symbols having the given prefix, using space as a hint
	 * 
	 * <p>
	 * As in {@link #chooseAny(String)}, if space is null or the constant space, then this will
	 * suggest from all symbols, via {@link #suggestAny(String, int)}. If space is given, and it is
	 * not the constant space, then this will suggest from symbols in the given space, via
	 * {@link #suggestBySpace(String, AddressSpace, int)}.
	 * 
	 * @param got the prefix
	 * @param space the space, or null
	 * @param max the maximum number of symbols to suggest
	 * @return the collection of symbol names
	 */
	public Collection<String> getSuggestions(String got, AddressSpace space, int max) {
		if (space == null || space.isConstantSpace()) {
			return suggestAny(got, max);
		}
		return suggestBySpace(got, space, max);
	}
}
