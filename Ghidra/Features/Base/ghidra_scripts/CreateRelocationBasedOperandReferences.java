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
// This script creates references on scalar operands which can be directly 
// correlated to a symbol or equate via a relocation table entry.  Only symbols within
// byte-oriented address spaces will be considered.
//@category Analysis

import java.util.Iterator;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;

public class CreateRelocationBasedOperandReferences extends GhidraScript {
	
    @Override
    public void run() throws Exception {
		if (currentProgram == null) {
			popup("No active Program to analyze");
			return;
		}

		Listing listing = currentProgram.getListing();
		ReferenceManager refMgr = currentProgram.getReferenceManager();
		EquateTable equateTable = currentProgram.getEquateTable();
		SymbolTable symbolTable = currentProgram.getSymbolTable();

		RelocationTable relocationTable = currentProgram.getRelocationTable();
		if (relocationTable.getSize() == 0) {
			popup("Program does not have relocations");
			return;
		}

		Iterator<Relocation> relocations = relocationTable.getRelocations();

		monitor.initialize(relocationTable.getSize());
		int refCount = 0;

		while (relocations.hasNext()) {
			monitor.checkCanceled();
			Relocation r = relocations.next();
			monitor.incrementProgress(1);

			Instruction instr = listing.getInstructionAt(r.getAddress());
			if (instr == null) {
				continue;
			}

			Equate equate = null;
			Symbol symbol = null;
			long value;

			List<Symbol> symbols = symbolTable.getLabelOrFunctionSymbols(r.getSymbolName(), null);
			if (symbols.size() == 0) {
				// check for possible equate definition
				equate = equateTable.getEquate(r.getSymbolName());
				if (equate == null) {
					continue;
				}
				value = equate.getValue();
			}
			else if (symbols.size() == 1) {
				symbol = symbols.get(0);
				Address a = symbol.getAddress();
				if (a.getAddressSpace().getAddressableUnitSize() != 1) {
					continue;
				}
				value = a.getOffset();
			}
			else {
				continue;
			}

			Reference[] referencesFrom = null;

			int opCnt = instr.getNumOperands();
			for (int opIndex = 0; opIndex < opCnt; opIndex++) {
				Scalar scalar =
					getScalarOperand(instr.getDefaultOperandRepresentationList(opIndex));
				if (scalar == null || scalar.getUnsignedValue() != value) {
					continue;
				}
				if (referencesFrom == null) {
					referencesFrom = refMgr.getReferencesFrom(instr.getAddress());
				}
				if (hasReference(referencesFrom, opIndex)) {
					continue; // reference exists on operand
				}
				if (equateTable.getEquates(instr.getAddress(), opIndex).size() != 0) {
					continue; // equate reference exists on operand
				}
				if (symbol != null) {
					Reference ref = refMgr.addMemoryReference(instr.getAddress(),
						symbol.getAddress(), RefType.DATA, SourceType.ANALYSIS, opIndex);
					refMgr.setAssociation(symbol, ref);
				}
				else {
					equate.addReference(instr.getAddress(), opIndex);
				}
				++refCount;
				break;
			}

		}

		popup("Added " + refCount + " relocation-based references");
	}

	private Scalar getScalarOperand(List<Object> defaultOperandRepresentationList) {
		Scalar s = null;
		for (Object obj : defaultOperandRepresentationList) {
			if (obj instanceof String) {
				continue;
			}
			if (obj instanceof Character) {
				continue;
			}
			if (obj instanceof Scalar) {
				if (s != null) {
					// more than one scalar found
					return null;
				}
				s = (Scalar) obj;
			}
			else {
				// non-scalar found
				return null;
			}
		}
		return s;
	}

	private boolean hasReference(Reference[] referencesFrom, int opIndex) {
		for (Reference r : referencesFrom) {
			if (r.getOperandIndex() == opIndex) {
				return true;
			}
		}
		return false;
	}

}
