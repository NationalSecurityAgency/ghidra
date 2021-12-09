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

import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;

/**
 * <CODE>VariableLocation</CODE> provides information about the location
 * on a variable within a <CODE>Function</CODE>.
 */
public class VariableLocation extends FunctionLocation {

	private boolean isParameter;

	private int ordinalOrFirstUseOffset;
	private Address variableAddress; // will be NO_ADDRESS for return and auto-parameters

	@Override
	public String toString() {
		return super.toString() + ", isParameter = " + isParameter +
			", ordinalOrFirstUseOffset = " + ordinalOrFirstUseOffset + ", Variable Address = " +
			variableAddress;
	}

	/**
	 * Default constructor needed for restoring
	 * a variable location from XML.
	 */
	public VariableLocation() {
	}

	/**
	 * Create a new VariableLocation.
	 * 
	 * @param program the program of the location
	 * @param locationAddr the address of the listing location (i.e., referent code unit)
	 * @param var the variable associated with this location.
	 * @param index the index of the sub-piece on that variable (only the xrefs have subpieces
	 * @param charOffset the character position on the piece.
	 */
	public VariableLocation(Program program, Address locationAddr, Variable var, int index,
			int charOffset) {
		super(program, locationAddr, var.getFunction().getEntryPoint(), 0, index, charOffset);

		variableAddress = getVariableAddress(var);
		if (var instanceof Parameter) {
			isParameter = true;
			ordinalOrFirstUseOffset = ((Parameter) var).getOrdinal();
		}
		else {
			ordinalOrFirstUseOffset = var.getFirstUseOffset();
		}
	}

	/**
	 * Create a new VariableLocation.
	 * 
	 * @param program the program of the location
	 * @param var the variable associated with this location.
	 * @param index the index of the sub-piece on that variable (only the xrefs have subpieces
	 * @param charOffset the character position on the piece.
	 */
	public VariableLocation(Program program, Variable var, int index, int charOffset) {
		this(program, var.getFunction().getEntryPoint(), var, index, charOffset);
	}

	/**
	 * Get the variable associated with this variable location
	 * @return associated function variable
	 */
	public Variable getVariable() {
		Function function = program.getFunctionManager().getFunctionAt(functionAddr);
		if (function == null) {
			return null;
		}
		if (isParameter) { // return or parameter
			return function.getParameter(ordinalOrFirstUseOffset);
		}
		if (variableAddress == null || !variableAddress.isVariableAddress()) {
			return null;
		}
		for (Variable var : function.getLocalVariables()) {
			if (var.getFirstUseOffset() == ordinalOrFirstUseOffset &&
				var.getSymbol().getAddress().equals(variableAddress)) {
				return var;
			}
		}
		return null;
	}

	private Address getVariableAddress(Variable var) {
		Symbol sym = var.getSymbol();
		if (sym == null) {
			return Address.NO_ADDRESS; // auto-params have no symbol
		}
		if (sym.getProgram() != program) {
			// Attempt to locate corresponding variable symbol within the current program
			// to allow for use in Diff operations
			Symbol otherSym = SimpleDiffUtility.getVariableSymbol(sym, program);
			if (otherSym != null) {
				return otherSym.getAddress();
			}
			return Address.NO_ADDRESS;
		}
		return sym.getAddress();
	}

	/**
	 * Checks to see if this location is for the indicated variable.
	 * @param var the variable
	 * @return true if this location is for the specified variable.
	 */
	public boolean isLocationFor(Variable var) {
		if (!functionAddr.equals(var.getFunction().getEntryPoint())) {
			return false;
		}
		if (var instanceof Parameter) {
			return isParameter && (ordinalOrFirstUseOffset == ((Parameter) var).getOrdinal());
		}
		return (ordinalOrFirstUseOffset == var.getFirstUseOffset() && variableAddress.equals(getVariableAddress(var)));
	}

	public boolean isParameter() {
		return isParameter && ordinalOrFirstUseOffset != Parameter.RETURN_ORIDINAL;
	}

	public boolean isReturn() {
		return isParameter && ordinalOrFirstUseOffset == Parameter.RETURN_ORIDINAL;
	}

	@Override
	public boolean equals(Object object) {
		if (super.equals(object)) {
			VariableLocation loc = (VariableLocation) object;
			if (isParameter != loc.isParameter ||
				ordinalOrFirstUseOffset != loc.ordinalOrFirstUseOffset) {
				return false;
			}
			return isParameter || variableAddress.equals(loc.variableAddress);
		}
		return false;
	}

	@Override
	public int compareTo(ProgramLocation pl) {
		if (pl instanceof VariableLocation) {
			if (pl.getClass() == this.getClass() && pl.getAddress().equals(getAddress())) {
				// only compare here is not the same variable within the same function
				// otherwise defer to super
				VariableLocation otherLoc = (VariableLocation) pl;
				if (isParameter) {
					if (!otherLoc.isParameter) {
						return -1;
					}
					int retVal = ordinalOrFirstUseOffset - otherLoc.ordinalOrFirstUseOffset;
					if (retVal != 0) {
						return retVal;
					}
				}
				else {
					if (otherLoc.isParameter) {
						return 1;
					}
					// nulls may be returned for non-existing variables
					// which can't be compared against
					Variable var = getVariable();
					Variable otherVar = otherLoc.getVariable();
					if (var == null) {
						if (otherVar != null) {
							return 1;
						}
					}
					else if (otherVar == null) {
						return -1;
					}
					else {
						return var.compareTo(otherVar);
					}
				}
			}
		}
		return super.compareTo(pl);
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		isParameter = obj.getBoolean("_IS_PARAMETER", false);
		ordinalOrFirstUseOffset = obj.getInt("_ORDINAL_FIRST_USE_OFFSET", 0);
		variableAddress = Address.NO_ADDRESS; // corresponds to return parameter
		if (obj.hasValue("_VARIABLE_OFFSET")) {
			long offset = obj.getLong("_VARIABLE_OFFSET", -1L);
			if (offset != -1) {
				variableAddress = AddressSpace.VARIABLE_SPACE.getAddress(offset);
			}
		}
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putBoolean("_IS_PARAMETER", isParameter);
		obj.putInt("_ORDINAL_FIRST_USE_OFFSET", ordinalOrFirstUseOffset);
		if (variableAddress.isVariableAddress()) {
			obj.putLong("_VARIABLE_OFFSET", variableAddress.getOffset());
		}
	}

	@Override
	public boolean isValid(Program p) {
		if (!super.isValid(p)) {
			return false;
		}
		return getVariable() != null;
	}
}
