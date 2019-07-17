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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;

/**
 * Default behavior implementation of ContextEvaluator passed to SymbolicPropogator
 * 
 * Override methods to inspect context.
 * 
 */

public class ContextEvaluatorAdapter implements ContextEvaluator {
	@Override
	public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {
		return false;
	}

	@Override
	public boolean evaluateContext(VarnodeContext context, Instruction instr) {
		return false;
	}

	@Override
	public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop,
			Address constant, int size, RefType refType) {
		return null;
	}

	@Override
	public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop, Address address,
			int size, RefType refType) {
		return false;
	}

	@Override
	public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
		return false;
	}

	@Override
	public Long unknownValue(VarnodeContext context, Instruction instruction, Varnode node) {
		return null;
	}

	@Override
	public boolean followFalseConditionalBranches() {
		return true;
	}

	@Override
	public boolean evaluateSymbolicReference(VarnodeContext context, Instruction instr,
			Address address) {
		return false;
	}

	@Override
	public boolean allowAccess(VarnodeContext context, Address addr) {
		return false;
	}
}
