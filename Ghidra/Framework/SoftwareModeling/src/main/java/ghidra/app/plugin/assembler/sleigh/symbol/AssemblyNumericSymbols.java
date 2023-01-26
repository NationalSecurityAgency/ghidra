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
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * A context to hold various symbols offered to the assembler, usable where numbers are expected.
 */
public final class AssemblyNumericSymbols {
	public static final AssemblyNumericSymbols EMPTY = new AssemblyNumericSymbols();

	/**
	 * Collect labels derived from memory-mapped registers in a language
	 * 
	 * <p>
	 * TODO: Use of registers should be limited to operands whose size match the register size.
	 * 
	 * @param labels the destination map
	 * @param language the language
	 */
	private static NavigableMap<String, Set<Address>> collectLanguageLabels(Language language) {
		NavigableMap<String, Set<Address>> labels = new TreeMap<>();
		for (Register reg : language.getRegisters()) {
			// TODO/HACK: There ought to be a better mechanism describing suitable symbolic
			// substitutions for a given operand.
			if (!reg.getAddressSpace().isRegisterSpace()) {
				labels.computeIfAbsent(reg.getName(), n -> new HashSet<>()).add(reg.getAddress());
			}
		}
		return labels;
	}

	private static Stream<Address> streamAddresses(Symbol sym) {
		SymbolType symbolType = sym.getSymbolType();
		if (symbolType == SymbolType.LABEL) {
			return Stream.of(sym.getAddress());
		}
		if (symbolType == SymbolType.FUNCTION) {
			Function function = (Function) sym.getObject();
			Address[] thunks = function.getFunctionThunkAddresses(true);
			return thunks == null ? Stream.of(sym.getAddress())
					: Stream.concat(Stream.of(sym.getAddress()), Stream.of(thunks));
		}
		return Stream.of();
	}

	private static Stream<Address> streamNonExternalAddresses(Symbol sym) {
		return streamAddresses(sym).filter(a -> !a.isExternalAddress());
	}

	/**
	 * Collect equates from the program's database
	 * 
	 * @param equates the destination map
	 * @param programthe source program
	 */
	private static NavigableMap<String, Set<Long>> collectProgramEquates(Program program) {
		NavigableMap<String, Set<Long>> equates = new TreeMap<>();
		final Iterator<Equate> it = program.getEquateTable().getEquates();
		while (it.hasNext()) {
			Equate eq = it.next();
			// Thought is: If that's what the user sees, then that's what the user will type!
			equates.computeIfAbsent(eq.getDisplayName(), n -> new HashSet<>()).add(eq.getValue());
		}
		return equates;
	}

	/**
	 * Get symbols from a language, when no program is available
	 * 
	 * @param language the language
	 * @return the symbols
	 */
	public static AssemblyNumericSymbols fromLanguage(Language language) {
		return new AssemblyNumericSymbols(language);
	}

	/**
	 * Get symbols from a program (and its language)
	 * 
	 * @param program the program
	 * @return the symbols
	 */
	public static AssemblyNumericSymbols fromProgram(Program program) {
		return new AssemblyNumericSymbols(program);
	}

	public final NavigableMap<String, Set<Long>> programEquates;
	public final NavigableMap<String, Set<Address>> languageLabels;
	private final Program program;

	private AssemblyNumericSymbols() {
		this.program = null;
		this.programEquates = new TreeMap<>();
		this.languageLabels = new TreeMap<>();
	}

	private AssemblyNumericSymbols(Language language) {
		this.program = null;
		this.programEquates = new TreeMap<>();
		this.languageLabels = collectLanguageLabels(language);
	}

	private AssemblyNumericSymbols(Program program) {
		this.program = program;
		this.programEquates = collectProgramEquates(program);
		this.languageLabels = collectLanguageLabels(program.getLanguage());
	}

	/**
	 * Choose any symbol with the given name
	 * 
	 * <p>
	 * This will order equates first, then program labels, then language labels. For addresses, the
	 * value is its addressable word offset.
	 * 
	 * @param name the name
	 * @return the value, or null
	 */
	public Set<Long> chooseAll(String name) {
		Set<Long> result = new TreeSet<>();
		result.addAll(programEquates.getOrDefault(name, Set.of()));
		if (program != null) {
			StreamSupport.stream(program.getSymbolTable().getSymbols(name).spliterator(), false)
					.flatMap(sym -> streamNonExternalAddresses(sym))
					.forEach(a -> result.add(a.getAddressableWordOffset()));
		}
		for (Address address : languageLabels.getOrDefault(name, Set.of())) {
			result.add(address.getAddressableWordOffset());
		}
		return result;
	}

	/**
	 * Choose a label with the given name in the given space
	 * 
	 * @param name the name
	 * @param space the address space
	 * @return the addressable word offset of the found label, or null
	 */
	public Set<Long> chooseBySpace(String name, AddressSpace space) {
		Set<Long> result = new TreeSet<>();
		if (program != null) {
			StreamSupport.stream(program.getSymbolTable().getSymbols(name).spliterator(), false)
					.flatMap(sym -> streamAddresses(sym))
					.filter(a -> a.getAddressSpace() == space)
					.forEach(a -> result.add(a.getAddressableWordOffset()));
		}
		for (Address address : languageLabels.getOrDefault(name, Set.of())) {
			if (address.getAddressSpace() != space) {
				continue;
			}
			result.add(address.getAddressableWordOffset());
		}
		return result;
	}

	/**
	 * Choose a symbol with the given name, using the space as a hint
	 * 
	 * <p>
	 * If a space is not given, or if that space is the constant space, then this will choose from
	 * all symbols, via {@link #chooseAll(String)}. If a space is given, and it is not the constant
	 * space, then this will choose from symbols in the given space, via
	 * {@link #chooseBySpace(String, AddressSpace)}.
	 * 
	 * @param name the name
	 * @param space the address space, or null
	 * @return the equate value, or label addressable word offset, or null
	 */
	public Set<Long> choose(String name, AddressSpace space) {
		if (space == null || space.isConstantSpace()) {
			return chooseAll(name);
		}
		return chooseBySpace(name, space);
	}

	private void suggestFrom(List<String> result, String got, NavigableSet<String> keys, int max) {
		int count = 0;
		for (String k : keys.tailSet(got)) {
			if (count >= max || !k.startsWith(got)) {
				return;
			}
			result.add(k);
			count++;
		}
	}

	private void suggestFromBySpace(List<String> result, String got,
			NavigableMap<String, Set<Address>> labels, int max, AddressSpace space) {
		int count = 0;
		for (Entry<String, Set<Address>> ent : labels.entrySet()) {
			if (count >= max || !ent.getKey().startsWith(got)) {
				return;
			}
			if (!ent.getValue().stream().anyMatch(a -> a.getAddressSpace() == space)) {
				continue;
			}
			result.add(ent.getKey());
			count++;
		}
	}

	private void suggestFromProgramAny(List<String> result, String got, int max) {
		int count = 0;
		for (Symbol s : program.getSymbolTable().scanSymbolsByName(got)) {
			if (count >= max || !s.getName().startsWith(got)) {
				return;
			}
			if (streamNonExternalAddresses(s).findAny().isEmpty()) {
				continue;
			}
			result.add(s.getName());
			count++;
		}
	}

	private void suggestFromProgramBySpace(List<String> result, String got, int max,
			AddressSpace space) {
		int count = 0;
		for (Symbol s : program.getSymbolTable().scanSymbolsByName(got)) {
			if (count >= max || !s.getName().startsWith(got)) {
				return;
			}
			if (!streamAddresses(s).anyMatch(a -> a.getAddressSpace() == space)) {
				continue;
			}
			result.add(s.getName());
			count++;
		}
	}

	/**
	 * Suggest up to max symbols having the given prefix
	 * 
	 * @param got the prefix
	 * @param max the maximum number of symbols to suggest
	 * @return the collection of symbol names
	 */
	public Collection<String> suggestAny(String got, int max) {
		List<String> result = new ArrayList<>();
		suggestFrom(result, got, languageLabels.navigableKeySet(), max);
		if (program == null) {
			return result;
		}
		suggestFrom(result, got, programEquates.navigableKeySet(), max);
		suggestFromProgramAny(result, got, max);
		Collections.sort(result);
		if (result.size() > max) {
			return result.subList(0, max);
		}
		return result;
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
		List<String> result = new ArrayList<>();
		suggestFromBySpace(result, got, languageLabels, max, space);
		if (program == null) {
			return result;
		}
		suggestFromProgramBySpace(result, got, max, space);
		Collections.sort(result);
		if (result.size() > max) {
			return result.subList(0, max);
		}
		return result;
	}

	/**
	 * Suggest up to max symbols having the given prefix, using space as a hint
	 * 
	 * <p>
	 * As in {@link #chooseAll(String)}, if space is null or the constant space, then this will
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
