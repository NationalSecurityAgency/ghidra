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
import java.util.regex.Pattern;

import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyNumericSymbols;

public class WildAssemblySubtableTerminal extends WildAssemblyTerminal {
	// Yes, leave the ! part of the spec/name
	public static final Pattern PAT_WILD_TREE = Pattern.compile("`(?<spec>![^`]*)`");

	public WildAssemblySubtableTerminal(String name) {
		super("`WILD`-" + name);
	}

	@Override
	public String toString() {
		return "[" + name + "]";
	}

	@Override
	protected Pattern getPattern() {
		return PAT_WILD_TREE;
	}

	@Override
	public Collection<String> getSuggestions(String got, AssemblyNumericSymbols symbols) {
		return List.of("`!Q1`");
	}
}
