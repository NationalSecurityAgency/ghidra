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
package ghidra.app.plugin.assembler.sleigh.tree;

import java.io.PrintStream;

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyStringTerminal;
import ghidra.app.plugin.assembler.sleigh.symbol.AssemblyTerminal;

/**
 * A string token
 * 
 * @see AssemblyStringTerminal
 */
public class AssemblyParseToken extends AssemblyParseTreeNode {
	protected final AssemblyTerminal term;
	protected final String str;

	/**
	 * Construct a new token having the given string value
	 * @param grammar the grammar containing the terminal
	 * @param term the terminal that matched this token
	 * @param str the portion of the input comprising this token
	 */
	public AssemblyParseToken(AssemblyGrammar grammar, AssemblyTerminal term, String str) {
		super(grammar);
		this.term = term;
		this.str = str;
	}

	@Override
	public int hashCode() {
		int result = term.hashCode();
		result *= 31;
		result += str.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		AssemblyParseToken that = (AssemblyParseToken) obj;
		if (!this.term.equals(that.term)) {
			return false;
		}
		if (!this.str.equals(that.str)) {
			return false;
		}
		return true;
	}

	/**
	 * Get the portion of the input comprising the token
	 * @return the string value
	 */
	public String getString() {
		return str;
	}

	@Override
	public AssemblyTerminal getSym() {
		return term;
	}

	@Override
	protected void print(PrintStream out, String indent) {
		out.println(indent + term + " := " + toString());
	}

	@Override
	public String toString() {
		return "'" + str + "'";
	}

	@Override
	public String generateString() {
		return str;
	}
}
