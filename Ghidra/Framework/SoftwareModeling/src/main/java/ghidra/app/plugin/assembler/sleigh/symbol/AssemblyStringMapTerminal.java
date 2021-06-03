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

import org.apache.commons.collections4.MultiValuedMap;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;
import ghidra.app.plugin.processors.sleigh.symbol.VarnodeListSymbol;

/**
 * A terminal that accepts only a particular set of strings, mapping each to a numeric value
 * 
 * @see ghidra.app.plugin.processors.sleigh.symbol.NameSymbol NameSymbol
 * @see VarnodeListSymbol
 */
public class AssemblyStringMapTerminal extends AssemblyTerminal {
	protected final MultiValuedMap<String, Integer> map;

	/**
	 * Construct a terminal with the given name, accepting only the keys of a given map
	 * @param name the name
	 * @param map the map from display text to token value
	 */
	public AssemblyStringMapTerminal(String name, MultiValuedMap<String, Integer> map) {
		super(name);
		this.map = map;
	}

	@Override
	public Collection<AssemblyParseNumericToken> match(String buffer, int pos,
			AssemblyGrammar grammar, Map<String, Long> labels) {
		Collection<AssemblyParseNumericToken> result = new LinkedHashSet<>();
		for (Entry<String, Integer> ent : map.entries()) {
			String str = ent.getKey();
			if (buffer.regionMatches(pos, str, 0, str.length())) {
				result.add(new AssemblyParseNumericToken(grammar, this, str, ent.getValue()));
			}
		}
		return result;
	}

	@Override
	public Collection<String> getSuggestions(String string, Map<String, Long> labels) {
		return map.keySet();
	}

	@Override
	public String toString() {
		return "[list:" + name + "]";
	}
}
