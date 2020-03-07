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
package ghidra.program.util;

import java.util.List;

import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.SymbolPath;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;

/**
 * The <CODE>LableFieldLocation</CODE> class contains specific location information
 * within the LABEL field of a CodeUnitLocation object.
 */
public class LabelFieldLocation extends CodeUnitLocation {
	private SymbolPath symbolPath;

	/**
	 * Default constructor needed for restoring
	 * a label field location from XML
	 */
	public LabelFieldLocation() {

	}

	/**
	 * Construct a new LabelFieldLocation.
	 *
	 * @param program the program of the location
	 * @param addr address of the location; should not be null
	 * @param componentPath array of indexes for each nested data component; the
	 * index is the data component's index within its parent; may be null
	 * @param label the label String at this location.
	 * @param row the row in list of labels as displayed by the label field.  Only used for
	 * program location comparison purposes.
	 * @param charOffset the column position within the label string for this location.
	 */
	public LabelFieldLocation(Program program, Address addr, int[] componentPath, String label,
			Namespace namespace, int row, int charOffset) {

		super(program, addr, componentPath, row, 0, charOffset);
		if (namespace == null || namespace.isGlobal()) {
			symbolPath = new SymbolPath(label);
		}
		else {
			symbolPath = new SymbolPath(new SymbolPath(namespace.getSymbol()), label);
		}
	}

	/**
	 * Construct a new LabelFieldLocation where the namespace is global, primary is false, and
	 * the cursor location is at row 0, column 0;
	 * @param program the program of the location.
	 * @param addr the address of the location.
	 * @param label the name of the symbol for this label location.
	 */
	public LabelFieldLocation(Program program, Address addr, String label) {
		this(program, addr, null, label, null, 0, 0);
	}

	/**
	 * Construct a new LabelFieldLocation.<P>
	 * @param program the program of the location.
	 * @param addr address of the location; should not be null
	 * @param label the label String at this location.
	 * @param namespace the namespace for the label. Null will default to the global namespace.
	 * @param row the row in list of labels as displayed by the label field.  Only used for
	 * program location comparison purposes.
	 */
	public LabelFieldLocation(Program program, Address addr, String label, Namespace namespace,
			int row) {
		this(program, addr, null, label, namespace, row, 0);
	}

	/**
	 * Creates a label field location using the specified symbol
	 * and an index of 0.
	 * @param s the symbol to use when creating the location
	 */
	public LabelFieldLocation(Symbol s) {
		this(s, 0, 0);
	}

	/**
	 * Creates a label field location using the specified symbol
	 * and the specified field index.
	 * @param s     the symbol to use when creating the location
	 * @param row the row of the symbol.
	 * @param charOffset the position within the label string for this location
	 */
	public LabelFieldLocation(Symbol s, int row, int charOffset) {
		this(s.getProgram(), s.getAddress(), null, s.getName(), s.getParentNamespace(), row,
			charOffset);
		if (s.getSymbolType() != SymbolType.LABEL && s.getSymbolType() != SymbolType.FUNCTION) {
			throw new IllegalArgumentException("Code symbol expected");
		}
	}

	/**
	 * Return the label string at this location.
	 */
	public String getName() {
		return symbolPath.getName();
	}

	/**
	 * Returns the symbol at this LabelFieldLocation
	 * NOTE: currently a null symbol will be returned for default thunk functions
	 * @return the symbol at this LabelFieldLocation or null if symbol lookup fails
	 */
	public Symbol getSymbol() {
		List<Symbol> symbols = NamespaceUtils.getSymbols(symbolPath, program);
		for (Symbol symbol : symbols) {
			if (symbol.getAddress().equals(getAddress())) {
				return symbol;
			}
		}
		return null;
	}

	/**
	 * Returns the symbol path which corresponds to the label location
	 * @return symbol path
	 */
	public SymbolPath getSymbolPath() {
		return symbolPath;
	}

	/**
	 * Returns a String representation of this location.
	 */
	@Override
	public String toString() {
		return super.toString() + ", Label = " + symbolPath.getPath();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + symbolPath.hashCode();
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!super.equals(obj)) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		LabelFieldLocation other = (LabelFieldLocation) obj;
		return symbolPath.equals(other.symbolPath);
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_SYMBOL_PATH", symbolPath.asArray());
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		String[] symbolPathArray = obj.getStrings("_SYMBOL_PATH", null);
		symbolPath = symbolPathArray == null ? new SymbolPath("") : new SymbolPath(symbolPathArray);
	}
}
