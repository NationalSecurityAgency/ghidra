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
package ghidra.app.util.bin.format.coff.relocation;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import ghidra.app.util.bin.format.RelocationException;
import ghidra.app.util.bin.format.coff.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/**
 * <code>CoffRelocationContext</code> provide COFF relocation context data to be used by 
 * {@link CoffRelocationHandler} during processing of relocations.
 */
public class CoffRelocationContext {

	private final Program program;
	private final CoffFileHeader header;
	private final Map<CoffSymbol, Symbol> symbolsMap;

	private final Map<String, Object> contextMap = new HashMap<>();
	private CoffSectionHeader section;

	/**
	 * Construct COFF relocation context
	 * @param program program to which relocations are applied
	 * @param header COFF file header
	 * @param symbolsMap symbol lookup map
	 */
	public CoffRelocationContext(Program program, CoffFileHeader header,
			Map<CoffSymbol, Symbol> symbolsMap) {
		this.program = program;
		this.header = header;
		this.symbolsMap = symbolsMap;
	}

	/**
	 * Reset context at start of COFF section relocation processing
	 * @param coffSection COFF section
	 */
	public void resetContext(CoffSectionHeader coffSection) {
		this.section = coffSection;
		contextMap.clear();
	}

	/**
	 * Get program to which relocations are being applied
	 * @return program
	 */
	public Program getProgram() {
		return program;
	}

	/**
	 * Get COFF section to which relocations are being applied
	 * @return COFF section
	 */
	public CoffSectionHeader getSection() {
		return section;
	}

	/**
	 * Get symbol required to process a relocation.  Method should only be invoked
	 * when a symbol is required since some relocations may not require a symbol.
	 * @param relocation relocation whose related symbol should be returned
	 * @return relocation symbol
	 * @throws RelocationException if symbol not found
	 */
	public Symbol getSymbol(CoffRelocation relocation) throws RelocationException {
		Symbol symbol =
			symbolsMap.get(header.getSymbolAtIndex(relocation.getSymbolIndex()));
		if (symbol == null) {
			throw new RelocationException("missing required symbol");
		}
		return symbol;
	}

	/**
	 * Get address of symbol required to process a relocation.  Method should only be invoked
	 * when a symbol is required since some relocations may not require a symbol.
	 * @param relocation relocation whose related symbol should be returned
	 * @return relocation symbol
	 * @throws RelocationException if symbol not found
	 */
	public Address getSymbolAddress(CoffRelocation relocation) throws RelocationException {
		return getSymbol(relocation).getAddress();
	}

	/**
	 * Get and optionally compute context value for specified key
	 * @param key extension-specific context key
	 * @param mappingFunction function used to compute value if absent
	 * @return context value
	 */
	public Object computeContextValueIfAbsent(String key,
			Function<String, Object> mappingFunction) {
		return contextMap.computeIfAbsent(key, mappingFunction);
	}

	/**
	 * Store context value for specified key
	 * @param key extension-specific context key
	 * @param value context value
	 */
	public void putContextValue(String key, Object value) {
		contextMap.put(key, value);
	}

	/**
	 * Get context value for specified key
	 * @param key extension-specific key
	 * @return context value or null if absent
	 */
	public Object getContextValue(String key) {
		return contextMap.get(key);
	}

}
