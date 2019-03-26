/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.util.viewer.field;

import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;

/**
 * A version of {@link BrowserCodeUnitFormat} that changes how labels are rendered in offcut 
 * situations.
 */
public class LabelCodeUnitFormat extends BrowserCodeUnitFormat {

	public LabelCodeUnitFormat(ToolOptions fieldOptions) {
		super(fieldOptions, true);
	}

	@Override
	protected String getOffcutLabelStringForInstruction(Address offcutAddress,
			Instruction instruction) {
		Program program = instruction.getProgram();
		Symbol offsym = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address instructionAddress = instruction.getMinAddress();
		long diff = offcutAddress.subtract(instructionAddress);
		if (!offsym.isDynamic()) {
			return getDefaultOffcutString(offsym, instruction, diff, true);
		}

		Symbol containingSymbol = program.getSymbolTable().getPrimarySymbol(instructionAddress);
		if (containingSymbol != null) {
			return containingSymbol.getName() + PLUS + diff;
		}
		return getDefaultOffcutString(offsym, instruction, diff, true);
	}

	@Override
	protected String getOffcutDataString(Address offcutAddress, Data data) {
		Program program = data.getProgram();
		Symbol offcutSymbol = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address dataAddress = data.getMinAddress();
		int diff = (int) offcutAddress.subtract(dataAddress);
		if (!offcutSymbol.isDynamic()) {
			return getDefaultOffcutString(offcutSymbol, data, diff, true);
		}

		DataType dt = data.getBaseDataType();
		String prefix = getPrefixForStringData(data, dataAddress, diff, dt);
		if (prefix != null) {
			String addressString = SymbolUtilities.getAddressString(dataAddress);
			return addOffcutInformation(prefix, addressString, diff, true);
		}

		return getDefaultOffcutString(offcutSymbol, data, diff, true);
	}

}
