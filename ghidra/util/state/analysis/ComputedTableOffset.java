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
package ghidra.util.state.analysis;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.state.VarnodeOperation;

class ComputedTableOffset {
	
	private final int factor;
	private final Varnode indexValue;
	
	
	ComputedTableOffset(Varnode indexValue, int factor) {
		this.indexValue = indexValue;
		this.factor = factor;
	}

	/**
	 * Returns the index value Varnode or VarnodeOperation.
	 */
	Varnode getIndexValue() {
		return indexValue;
	}
	
	/**
	 * Returns table entry size in bytes
	 */
	int getTableEntrySize() {
		return factor;
	}
	
	/**
	 * Get the ComputedTableOffset which corresponds to the specified input varnode v.
	 * No qualification is performed.
	 * @param addrFactory
	 * @param v potential input value which corresponds to the computed offset into a switch table
	 * @return ComputedTableOffset object
	 */
	static ComputedTableOffset getComputedTableOffset(Varnode v) {
		long factor;
		Varnode indexValue = null;
		if (v instanceof VarnodeOperation) {
			VarnodeOperation computedTableOffsetOperation = (VarnodeOperation)v;
			int opcode = computedTableOffsetOperation.getPCodeOp().getOpcode();
			if (opcode != PcodeOp.INT_MULT && opcode != PcodeOp.INT_LEFT) {
				return null;
			}
			Varnode[] inputValues = computedTableOffsetOperation.getInputValues();
			if (inputValues[1].isConstant()) {
				factor = inputValues[1].getOffset();
				if (opcode == PcodeOp.INT_LEFT) {
					factor = 1L << factor;
				}
				indexValue = inputValues[0];
			}
			else if (opcode == PcodeOp.INT_MULT && inputValues[0].isConstant()) {
				factor = inputValues[0].getOffset();
				indexValue = inputValues[1];
			}
			else {
				factor = 1;
				indexValue = v;
			}
			if (factor <= 0 || factor > 8) {
				// Unsupported factor
				return null;
			}
		}
		else {
			factor = 1;
			indexValue = v;
		}
		if (indexValue instanceof VarnodeOperation) {
			// Ignore zero-extend operation which is stored in unique variable 
			// and can not be used by a subsequent instruction
			VarnodeOperation op = (VarnodeOperation)indexValue;
			if (op.getPCodeOp().getOutput().isUnique() && op.getPCodeOp().getOpcode() == PcodeOp.INT_ZEXT) {
				indexValue = op.getInputValues()[0];
			}
		}
		return new ComputedTableOffset(indexValue, (int)factor);
	}

}
