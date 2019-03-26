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
// Cursor must be within a function.  Script assumes r1 is base register
// and prompts for offset from base register, data type, and symbol name.
// Within current function, the script creates a stack variable with the
// specified data type and symbol name and converts all "offset(base_register)"
// references to "symbol_name(base_register)" references.
//
//@category CustomerSubmission.Analysis
//@keybinding alt S

import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.data.DataTypeParser;

public class MakeStackRefs extends GhidraScript {

	@Override
	public void run() throws Exception {

		// stack base register
		int reg = 1;

		// get stack offset for variable
		int stkOffset = 0;
		try {
			stkOffset = Integer.parseInt(askString("Stack Offset", "Stack offset (hex):"), 16);
		}
		catch (NumberFormatException e) {
			println("Invalid offset");
			return;
		}

		// get data type for variable
		DataTypeSelectionDialog dTypeDialog =
			new DataTypeSelectionDialog(state.getTool(), currentProgram.getDataTypeManager(),
				0xffff, DataTypeParser.AllowedDataTypes.ALL);
		dTypeDialog.setTitle("Variable Data Type");
		state.getTool().showDialog(dTypeDialog);
		DataType dType = dTypeDialog.getUserChosenDataType();
		if (dType == null)
			return;

		// get variable name
		String varName = askString("Variable Name", "Variable name:", "default");

		// define masks that isolate instr codes and register bits
		int lsxMask = 0xec1f0000; // l[whb]z & st[whb] instrs
		int addMask = 0xfc1f8000; // addi instrs

		// define values we want to match for each instr type
		int lswVal = 0x80000000 | (reg << 16); // lwz/stw: 100x 00xx xxxR RRRR + d
		int lshVal = 0xa0000000 | (reg << 16); // lhz/sth: 101x 00xx xxxR RRRR + d
		int lsbVal = 0x88000000 | (reg << 16); // lbz/stb: 100x 10xx xxxR RRRR + d
		int addVal = 0x38000000 | (reg << 16); // addi: 0011 10xx xxxR RRRR + SIMM

		// get Memory for later use and init stkRefCount
		Memory mem = currentProgram.getMemory();
		int stkRefCount = 0;

		// get function start and end addresses
		Function f = getFunctionContaining(currentAddress);
		if (f == null) {
			println("No function found at current address");
			return;
		}
		Address funcStart = f.getEntryPoint();
		Address funcEnd = f.getBody().getMaxAddress();
		println("Func start: 0x" + funcStart + ", Func end: " + funcEnd);

		// get stack frame size
		int frameSize = f.getStackFrame().getFrameSize();

		// ensure that frameSize is set properly
		for (Address addr = funcStart; addr.getOffset() < funcEnd.getOffset(); addr = addr.add(4)) {
			if ((mem.getInt(addr) & 0xffff0000) == 0x94210000) {
				frameSize = mem.getInt(addr) & 0xffff;
				frameSize = -(frameSize | 0xffff0000); // extend sign & negate
				f.getStackFrame().setLocalSize(frameSize);
				println("Set stack size to 0x" + Integer.toHexString(frameSize));
				break;
			}
		}

		// calculate Ghidra stack frame offset
		// (which uses the other end of the stack frame as the base)
		int gOffset = -(frameSize - stkOffset);

		// if no variable name was given, construct a default name
		if (varName.equals("default")) {
			varName = "local_" + (-gOffset);
		}

		// create data at the specified offset (if it doesn't exist)
		StackFrame sf = f.getStackFrame();
		if (sf.getVariableContaining(gOffset) == null) {
			sf.createVariable(varName, gOffset, dType, SourceType.USER_DEFINED);
			println("Created stack variable at Ghidra offset -0x" + Integer.toHexString(-gOffset));
		}

		// scan instrs in function and create requested stack refs
		for (Address addr = funcStart; addr.getOffset() < funcEnd.getOffset(); addr = addr.add(4)) {

			boolean makeStkVar = false;
			int opIndex = 0;

			if ((mem.getInt(addr) & lsxMask) == lswVal) {
				makeStkVar = true;
				opIndex = 1;
			}
			else if ((mem.getInt(addr) & lsxMask) == lshVal) {
				makeStkVar = true;
				opIndex = 1;
			}
			else if ((mem.getInt(addr) & lsxMask) == lsbVal) {
				makeStkVar = true;
				opIndex = 1;
			}
			else if ((mem.getInt(addr) & addMask) == addVal) {
				makeStkVar = true;
				opIndex = 2;
			}

			int offset = mem.getInt(addr) & 0xffff;
			if (makeStkVar && (offset == stkOffset)) {
				createStackReference(getInstructionAt(addr), opIndex, gOffset, true);
				stkRefCount += 1;
			}
		}

		println("Created " + stkRefCount + " stack references");
	}
}
