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

/**
 * A terminal that accepts only a particular numeric value
 * 
 * This is different from a fixed string, because it will accept any encoding of the given numeric
 * value.
 */
public class AssemblyFixedNumericTerminal extends AssemblyNumericTerminal {
	private final long val;

	/**
	 * Construct a terminal that accepts only the given numeric value
	 * @param val the value to accept
	 */
	public AssemblyFixedNumericTerminal(long val) {
		super("" + val, 0);
		this.val = val;
	}

	@Override
	public String toString() {
		return "" + val;
	}

	@Override
	public Collection<String> getSuggestions(String got, Map<String, Long> labels) {
		return Collections.singleton("" + val);
	}

	@Override
	public Collection<AssemblyParseNumericToken> match(String buffer, int pos,
			AssemblyGrammar grammar, Map<String, Long> labels) {
		// TODO: Allow label substitution here? For now, no.
		Collection<AssemblyParseNumericToken> toks =
			new HashSet<>(super.match(buffer, pos, grammar, new HashMap<String, Long>()));
		Iterator<AssemblyParseNumericToken> tokit = toks.iterator();
		while (tokit.hasNext()) {
			AssemblyParseNumericToken tok = tokit.next();
			if (tok.getNumericValue() != val) {
				tokit.remove();
			}
		}
		return toks;
	}
}
