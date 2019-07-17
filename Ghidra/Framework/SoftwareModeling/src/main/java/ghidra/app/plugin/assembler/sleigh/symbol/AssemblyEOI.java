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
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;

/**
 * A terminal that accepts the end of input
 */
public class AssemblyEOI extends AssemblyTerminal {
	/** The end-of-input terminal */
	public static final AssemblyEOI EOI = new AssemblyEOI();

	private AssemblyEOI() {
		super("$");
	}

	@Override
	public String toString() {
		return "$";
	}

	@Override
	public Collection<AssemblyParseToken> match(String buffer, int pos, AssemblyGrammar grammar,
			Map<String, Long> labels) {
		if (pos == buffer.length()) {
			return Collections.singleton(new AssemblyParseToken(grammar, this, ""));
		}
		return Collections.emptySet();
	}

	@Override
	public Collection<String> getSuggestions(String got, Map<String, Long> labels) {
		return Collections.singleton("");
	}
}
