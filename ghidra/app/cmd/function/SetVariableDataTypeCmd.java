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
package ghidra.app.cmd.function;

import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.exception.InvalidInputException;

/**
 * Command to set the datatype on a stack variable.
 */
public class SetVariableDataTypeCmd implements Command {

	private final Address fnEntry;
	private final String varName;
	private final DataType dataType;
	private final SourceType source;

	private final boolean align;
	private final boolean force;

	private boolean isParm;
	private String status;

	/**
	 * Constructs a new command for setting the datatype on a stack/reg variable.
	 * Conflicting stack variables will be removed.
	 * @param var the variable for which to set the datatype.
	 * @param dataType the datatype to apply to the stack variable.
	 * @param source signature source
	 */
	public SetVariableDataTypeCmd(Variable var, DataType dataType, SourceType source) {
		this(var.getFunction().getEntryPoint(), var.getName(), dataType, source);
	}

	/**
	 * Constructs a new command for setting the datatype on a stack/reg variable.
	 * Conflicting stack variables will be removed.
	 * @param fnEntry
	 * @param varName
	 * @param dataType
	 * @param source signature source
	 */
	public SetVariableDataTypeCmd(Address fnEntry, String varName, DataType dataType,
			SourceType source) {
		this(fnEntry, varName, dataType, false, true, source);
	}

	/**
	* Constructs a new command for setting the datatype on a stack/reg variable
	* @param fnEntry
	 * @param varName
	 * @param dataType
	 * @param align maintain proper alignment/justification if supported by implementation (ignored for non-stack variables).
	* 			If false and this is a stack variable, the current stack address/offset will not change.
	* 			If true, the affect is implementation dependent since alignment can
	* 			not be performed without access to a compiler specification.
	 * @param force overwrite conflicting stack variables
	 * @param source signature source
	*/
	public SetVariableDataTypeCmd(Address fnEntry, String varName, DataType dataType, boolean align,
			boolean force, SourceType source) {
		this.fnEntry = fnEntry;
		this.varName = varName;
		this.dataType = dataType;
		this.align = align;
		this.force = force;
		this.source = source;
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#getName()
	 */
	@Override
	public String getName() {
		return "Set " + (isParm ? "Parameter" : "Variable") + " Data Type";
	}

	/**
	 *
	 * @see ghidra.framework.cmd.Command#applyTo(ghidra.framework.model.DomainObject)
	 */
	@Override
	public boolean applyTo(DomainObject obj) {
		if (!(obj instanceof Program)) {
			return false;
		}
		Program p = (Program) obj;

		Function f = p.getFunctionManager().getFunctionAt(fnEntry);
		if (f == null) {
			status = "Function not found";
			return false;
		}

		Symbol s = p.getSymbolTable().getParameterSymbol(varName, f);
		if (s == null) {
			s = p.getSymbolTable().getLocalVariableSymbol(varName, f);
		}
		if (s == null) {
			status = "Variable not found";
			return false;
		}

		DataType dt = dataType;
		if (dataType instanceof FunctionDefinition || (dataType instanceof TypeDef &&
			((TypeDef) dataType).getDataType() instanceof FunctionDefinition)) {
			dt = new PointerDataType(dataType);
		}

		Variable var = (Variable) s.getObject();
		isParm = var instanceof Parameter;
		try {
			var.setDataType(dt, align, force, source);
		}
		catch (InvalidInputException e) {
			status = e.getMessage();
			return false;
		}
		return true;
	}

	/**
	 * @see ghidra.framework.cmd.Command#getStatusMsg()
	 */
	@Override
	public String getStatusMsg() {
		return status;
	}

}
