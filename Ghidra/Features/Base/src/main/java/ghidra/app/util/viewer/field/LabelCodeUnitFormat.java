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
package ghidra.app.util.viewer.field;

import javax.help.UnsupportedOperationException;

import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Symbol;

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
			Instruction instruction, Address markupAddress) {
		if (markupAddress != null) {
			throw new UnsupportedOperationException();
		}
		Program program = instruction.getProgram();
		Symbol offsym = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address instructionAddress = instruction.getMinAddress();
		long diff = offcutAddress.subtract(instructionAddress);
		boolean decorate = !offsym.isDynamic();
		boolean simplify = true;
		return getDefaultOffcutString(offsym, instruction, diff, decorate, simplify);
	}

	@Override
	protected String getOffcutDataString(Address offcutAddress, Data data) {
		Program program = data.getProgram();
		Symbol offcutSymbol = program.getSymbolTable().getPrimarySymbol(offcutAddress);
		Address dataAddress = data.getMinAddress();
		int diff = (int) offcutAddress.subtract(dataAddress);
		boolean simplify = !(offcutSymbol.isDynamic() && data.hasStringValue());
		boolean decorate = true;
		return getDefaultOffcutString(offcutSymbol, data, diff, decorate, simplify);
	}

}
