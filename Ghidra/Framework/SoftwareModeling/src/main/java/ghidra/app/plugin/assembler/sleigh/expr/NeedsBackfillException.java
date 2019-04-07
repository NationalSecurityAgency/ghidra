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
package ghidra.app.plugin.assembler.sleigh.expr;

/**
 * An exception to indicate that the solution of an expression is not yet known
 * 
 * Furthermore, it cannot be determined whether or not the expression is even solvable. When this
 * exception is thrown, a backfill record is placed on the encoded resolution indicating that
 * resolver must attempt to solve the expression again, once the encoding is otherwise complete.
 * This is needed, most notably, when an encoding depends on the address of the <em>next</em>
 * instruction, because the length of the current instruction is not known until resolution has
 * finished.
 * 
 * Backfill becomes a possibility when an expression depends on a symbol that is not (yet) defined.
 * Thus, as a matter of good record keeping, the exception takes the name of the missing symbol.
 */
public class NeedsBackfillException extends SolverException {
	private String symbol;

	/**
	 * Construct a backfill exception, resulting from the given missing symbol name
	 * @param symbol the missing symbol name
	 */
	public NeedsBackfillException(String symbol) {
		super("The symbol '" + symbol + "' is not yet available");
		this.symbol = symbol;
	}

	/**
	 * Retrieve the missing symbol name from the original solution attempt
	 * @return the missing symbol name
	 */
	public String getSymbol() {
		return symbol;
	}
}
