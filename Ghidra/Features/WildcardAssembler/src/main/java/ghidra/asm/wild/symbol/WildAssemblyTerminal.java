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
package ghidra.asm.wild.symbol;

import java.util.Collection;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal;
import ghidra.app.plugin.assembler.sleigh.tree.AssemblyParseToken;
import ghidra.asm.wild.tree.WildAssemblyParseToken;

public abstract class WildAssemblyTerminal extends AssemblyTerminal {
	public static final Pattern PAT_WILD = Pattern.compile("`(?<spec>[^`]*)`");

	public WildAssemblyTerminal(String name) {
		super(name);
	}

	protected Pattern getPattern() {
		return PAT_WILD;
	}

	@Override
	public Collection<? extends AssemblyParseToken> match(String buffer, int pos,
			AssemblyGrammar grammar, AssemblyNumericSymbols symbols) {
		Matcher matcher = getPattern().matcher(buffer).region(pos, buffer.length());
		if (!matcher.lookingAt()) {
			return List.of();
		}
		return List.of(
			new WildAssemblyParseToken(grammar, this, matcher.group(), matcher.group("spec")));
	}

	@Override
	public Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols) {
		return List.of("`Q1`");
	}
}
