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
package ghidra.app.plugin.core.debug.gui.variable;

import db.Transaction;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.trace.model.memory.TraceMemoryState;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public class DebuggerVariableViewerHighVarValue extends AbstractDebuggerVariableViewerVarValue {
	HighSymbol variable;

	public DebuggerVariableViewerHighVarValue(HighSymbol variable, byte[] value, Address address,
			String repr, DebuggerVariableViewerProvider provider, String error,
			TraceMemoryState state) {
		super(value, address, repr, provider, error, state);
		this.variable = variable;
	}

	@Override
	public DataType getDataType() {
		return variable.getDataType();
	}

	@Override
	public void setDataType(DataType dataType) {
		try (Transaction ignored = variable.getProgram().openTransaction("Set DataType")) {
			HighFunctionDBUtil.updateDBVariable(variable, null, dataType, SourceType.USER_DEFINED);
		}
		catch (final DuplicateNameException e) {
			Msg.showError(this, null, "Duplicate Name", e.getMessage());
		}
		catch (final InvalidInputException e) {
			Msg.showError(this, null, "Invalid Input", e.getMessage());
		}
	}

	@Override
	public String getSource() {
		return "Decompiler";
	}

	@Override
	public String getSymbol() {
		if (variable.getSymbol() == null) {
			return variable.getName();
		}
		return variable.getSymbol().getName();
	}

	@Override
	public void setSymbol(String symbol) {
		try (Transaction ignored = variable.getProgram().openTransaction("Rename Symbol")) {
			HighFunctionDBUtil.updateDBVariable(variable, symbol, null, SourceType.USER_DEFINED);
		}
		catch (final DuplicateNameException e) {
			Msg.showError(this, null, "Duplicate Name", e.getMessage());
		}
		catch (final InvalidInputException e) {
			Msg.showError(this, null, "Invalid Input", e.getMessage());
		}
	}
}
