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

import ghidra.app.plugin.assembler.sleigh.grammars.AssemblyGrammar;
import ghidra.app.plugin.assembler.sleigh.symbol.*;

/**
 * A token having a numeric value
 * 
 * @see AssemblyFixedNumericTerminal
 * @see AssemblyNumericMapTerminal
 * @see AssemblyNumericTerminal
 * @see AssemblyStringMapTerminal
 */
public class AssemblyParseNumericToken extends AssemblyParseToken {
	protected final long val;

	/**
	 * Construct a numeric terminal having the given string and numeric values
	 * @param grammar the grammar containing the terminal
	 * @param term the terminal that matched this token
	 * @param str the portion of the input comprising this token
	 * @param val the numeric value represented by this token
	 */
	public AssemblyParseNumericToken(AssemblyGrammar grammar, AssemblyTerminal term, String str,
			long val) {
		super(grammar, term, str);
		this.val = val;
	}

	@Override
	public int hashCode() {
		int result = term.hashCode();
		result *= 31;
		result += str.hashCode();
		result *= 31;
		result += Long.hashCode(val);
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		AssemblyParseNumericToken that = (AssemblyParseNumericToken) obj;
		if (!this.term.equals(that.term)) {
			return false;
		}
		if (!this.str.equals(that.str)) {
			return false;
		}
		if (this.val != that.val) {
			return false;
		}
		return true;
	}

	@Override
	public String toString() {
		return "'" + str + "'=>" + val;
	}

	/**
	 * Get the numeric value of the token
	 * @return the value
	 */
	public long getNumericValue() {
		return val;
	}

	@Override
	public boolean isNumeric() {
		return true;
	}
}
