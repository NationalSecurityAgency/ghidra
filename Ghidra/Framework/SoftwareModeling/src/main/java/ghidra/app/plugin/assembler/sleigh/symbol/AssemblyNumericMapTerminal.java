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

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseNumericToken;
import ghidra.app.plugin.processors.sleigh.symbol.ValueMapSymbol;

/**
 * A terminal that accepts only a particular set of numeric values, mapping each to another value
 * 
 * This often used for non-conventional numeric encodings.
 * @see ValueMapSymbol
 */
public class AssemblyNumericMapTerminal extends AssemblyNumericTerminal {
	protected final Map<Long, Integer> map;

	/**
	 * Construct a terminal with the given name, accepting only the keys of a given map
	 * @param name the name
	 * @param map the map from display value to token value
	 */
	public AssemblyNumericMapTerminal(String name, Map<Long, Integer> map) {
		super(name, 0);
		this.map = map;
	}

	@Override
	public Collection<AssemblyParseNumericToken> match(String buffer, int pos,
			AssemblyGrammar grammar, Map<String, Long> labels) {
		// NOTE: No label substitution
		Collection<AssemblyParseNumericToken> toks =
			new HashSet<>(super.match(buffer, pos, grammar, new HashMap<String, Long>()));
		Collection<AssemblyParseNumericToken> results = new LinkedHashSet<>();
		for (AssemblyParseNumericToken tok : toks) {
			Integer mapped = map.get(tok.getNumericValue());
			if (mapped == null) {
				continue;
			}
			results.add(new AssemblyParseNumericToken(grammar, this, tok.getString(), mapped));
		}
		return results;
	}

	@Override
	public Collection<String> getSuggestions(String got, Map<String, Long> labels) {
		Set<String> result = new HashSet<>();
		for (long k : map.keySet()) {
			result.add(Long.toString(k));
			result.add(Long.toHexString(k));
		}
		return result;
	}
}
