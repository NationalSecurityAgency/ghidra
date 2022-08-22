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
package ghidra.app.plugin.core.symtable;

import java.util.Objects;

import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

/**
 * <code>SymbolRowObject</code> provides a lightweight {@link Symbol}
 * table row object which may be used to reacquire an associated symbol.
 */
public class SymbolRowObject implements Comparable<SymbolRowObject> {

	private final long id;
	private final Program program;

	/**
	 * Construct a symbol row object.
	 * Symbol must supply program object.
	 * @param s program symbol
	 */
	public SymbolRowObject(Symbol s) {
		id = s.getID();
		program = Objects.requireNonNull(s.getProgram());
	}

	/**
	 * Constructor for subclass
	 * @param program symbol's associated program
	 * @param symbolId symbol ID
	 */
	protected SymbolRowObject(Program program, long symbolId) {
		this.id = symbolId;
		this.program = Objects.requireNonNull(program);
	}

	/**
	 * Get symbol id used to reacquire symbol from program
	 * @return symbol id
	 */
	public long getID() {
		return id;
	}

	/**
	 * Get the symbol associated with this row object.  If symbol no longer exists
	 * null may be returned.
	 * @return associated symbol or null if symbol not found or has been deleted
	 */
	public Symbol getSymbol() {
		return program != null ? program.getSymbolTable().getSymbol(id) : null;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof SymbolRowObject)) {
			return false;
		}
		SymbolRowObject other = (SymbolRowObject) obj;
		return id == other.id && program == other.program;
	}

	@Override
	public int hashCode() {
		return (int) (id ^ (id >>> 32));
	}

	@Override
	public String toString() {
		Symbol s = getSymbol();
		return s != null ? s.getName() : "<DELETED>";
	}

	/**
	 * The <code>AbstractSortedTableModel.EndOfChainComparator</code> makes it 
	 * neccessary to implement this method to avoid use of identity hash equality
	 * when two instances are otherwise equal.
	 */
	@Override
	public int compareTo(SymbolRowObject other) {
		return Long.compare(id, other.id);
	}

}
