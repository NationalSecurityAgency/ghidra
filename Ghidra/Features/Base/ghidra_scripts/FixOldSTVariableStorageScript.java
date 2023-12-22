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
//
// This fixup script is intended to be run against x86 programs created prior 
// to Ghidra 10.0.3 to update old ST0..ST7 floating point register
// locations assigned to function parameters and local variables.  The
// address assignment for these registers was changed with Ghidra 10.0.3 
// x86 slaspec change (GP-1228).
//
// This script can be run multiple times without harm
//@category Functions
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.InvalidInputException;

public class FixOldSTVariableStorageScript extends GhidraScript {

	private static final int ST_SIZE = 10;

	// See Ghidra/Processors/x86/data/languages/ia.sinc
	private static final long OLD_ST_BASE_OFFSET = 0x1000;
	private static final long OLD_ST_OFFSET_SPACING = ST_SIZE; // each offset 10-bytes from the previous

	// Must query new ST0 address since it may change again
	private static final long NEW_ST_OFFSET_SPACING = 16; // each offset 16-bytes from the previous

	@Override
	protected void run() throws Exception {

		if (currentProgram == null || !"x86".equals(currentProgram.getLanguage().getProcessor().toString())) {
			popup("Script supports x86 programs only");
			return;
		}
		
		// Spot check new ST0 placement
		Register st0 = currentProgram.getRegister("ST0");
		Register st1 = currentProgram.getRegister("ST1");
		if (st0 == null || st1 == null) {
			popup("Unsupported x86 language");
			return;
		}

		long st0Offset = st0.getAddress().getOffset();
		long st1Offset = st1.getAddress().getOffset();
		if (st0Offset == OLD_ST_BASE_OFFSET || (st1Offset - st0Offset) != NEW_ST_OFFSET_SPACING) {
			popup("Unsupported x86 ST register placement");
			return;
		}

		STRegisterFixup stRegisterFixup = new STRegisterFixup(st0Offset);
		int count = 0;
		
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		for (Symbol s : symbolTable.getDefinedSymbols()) {
			SymbolType type = s.getSymbolType();
			if (type == SymbolType.PARAMETER || type == SymbolType.LOCAL_VAR) {
				if (stRegisterFixup.fixupVariableStorage((Variable) s.getObject())) {
					++count;
				}
			}
			else if (type == SymbolType.FUNCTION) {
				Function function = (Function) s.getObject();
				if (stRegisterFixup.fixupVariableStorage(function.getReturn())) {
					++count;
				}
			}
		}

		if (count != 0) {
			popup("Fixed " + count + " ST register uses");
		}
		else {
			popup("No old ST register uses were found");
		}
	}

	private class STRegisterFixup {

		private Set<Varnode> oldSTVarnodes; // ST0..ST7
		private long newStBaseOffset;

		STRegisterFixup(long newStBaseOffset) {
			this.newStBaseOffset = newStBaseOffset;

			AddressSpace registerSpace = currentProgram.getAddressFactory().getRegisterSpace();

			long oldSTBaseOffset = OLD_ST_BASE_OFFSET;
			oldSTVarnodes = Set.of(
				new Varnode(registerSpace.getAddress(oldSTBaseOffset),
					ST_SIZE), // Old ST0 at 0x1000, now at 0x1106
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + OLD_ST_OFFSET_SPACING),
					ST_SIZE), // Old ST1 at 0x100a, now at 0x1116
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (2 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE), // Old ST2 at 0x1014, now at 0x1126
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (3 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE), // Old ST3 at 0x101e, now at 0x1136
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (4 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE), // Old ST4 at 0x1028, now at 0x1146
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (5 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE), // Old ST5 at 0x1032, now at 0x1156
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (6 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE), // Old ST6 at 0x103c, now at 0x1166
				new Varnode(registerSpace.getAddress(oldSTBaseOffset + (7 * OLD_ST_OFFSET_SPACING)),
					ST_SIZE)  // Old ST7 at 0x1046*, now at 0x1176                                                    // Old ST7 at 0x1046, now at 0x1176
			);

		}

		private boolean fixupVariableStorage(Variable var) {
			VariableStorage varStore = var.getVariableStorage();
			Varnode[] varnodes = varStore.getVarnodes();
			if (fixupStorageVarnodes(varnodes)) {
				try {
					var.setDataType(var.getDataType(),
						new VariableStorage(currentProgram, varnodes), false, var.getSource());
				}
				catch (InvalidInputException e) {
					throw new AssertionError("Unexpected error for ST register varnode assignment",
						e);
				}
				return true;
			}
			return false;
		}

		private boolean fixupStorageVarnodes(Varnode[] varnodes) {
			boolean hasFixup = false;
			for (int i = 0; i < varnodes.length; i++) {
				Varnode v = getReplacement(varnodes[i]);
				if (v != null) {
					hasFixup = true;
					varnodes[i] = v;
				}
			}
			return hasFixup;
		}

		Varnode getReplacement(Varnode v) {
			if (!oldSTVarnodes.contains(v)) {
				return null;
			}
			Address regAddr = v.getAddress();
			long stOffset = regAddr.getOffset() - OLD_ST_BASE_OFFSET;
			long stIndex = stOffset / OLD_ST_OFFSET_SPACING;

			// Form updated ST varnode
			stOffset = newStBaseOffset + (stIndex * NEW_ST_OFFSET_SPACING);
			return new Varnode(regAddr.getNewAddress(stOffset), 10);
		}


	}

}
