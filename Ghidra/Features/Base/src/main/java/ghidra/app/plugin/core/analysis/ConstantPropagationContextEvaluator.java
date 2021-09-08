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
package ghidra.app.plugin.core.analysis;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ContextEvaluatorAdapter;
import ghidra.program.util.VarnodeContext;

/** 
 * The ConstantPropogatorEvaluator is used as the evaluator for the SymbolicPropagator when finding constant
 * references and laying them down for a generic processor.  Extend this class to add additional checks
 * and behaviors necessary for a unique processor such as the PowerPC.
 * 
 * This implementation checks values that are problematic and will not make references to those locations.
 *     0-256, 0xffffffff, 0xffff, 0xfffffffe
 * For some embedded processors these locations or these locations in certain address spaces are OK,
 * so the evaluateConstant and evaluateReference should be overridden.
 * 
 * The base implementation supports setting of an option to trust values read from writable memory.
 * 
 * An addressset of locations that were computed jump flows where the flow is unknown is
 * available in a destination address set.
 */

public class ConstantPropagationContextEvaluator extends ContextEvaluatorAdapter {
	protected AddressSet destSet = new AddressSet();
	private boolean trustMemoryWrite = false;
	private long minStoreLoadOffset = 4;
	private long minSpeculativeOffset = 1024;   // from the beginning of memory
	private long maxSpeculativeOffset = 256;    // from the end of memory

	public ConstantPropagationContextEvaluator() {
	}

	/**
	 * @param trustMemoryWrite - true to trust values read from memory that is marked writable
	 */
	public ConstantPropagationContextEvaluator(boolean trustMemoryWrite) {
		this.trustMemoryWrite = trustMemoryWrite;
	}

	public ConstantPropagationContextEvaluator(boolean trustWriteMemOption,
			long minStoreLoadRefAddress, long minSpeculativeRefAddress,
			long maxSpeculativeRefAddress) {
		this(trustWriteMemOption);
		this.minStoreLoadOffset = minStoreLoadRefAddress;
		this.maxSpeculativeOffset = maxSpeculativeRefAddress;
	}

	/**
	 * The computed destination set is useful if follow on switch analysis is to be done.
	 * 
	 * @return a set of destinations that have computed flow where the flow is unknown
	 */
	public AddressSet getDestinationSet() {
		return destSet;
	}

	/**
	 * If you override this method, and the default behavior of checking 0-256 and mask values is desired,
	 * call super.evaluateConstant() in your overriden method.
	 */
	@Override
	public Address evaluateConstant(VarnodeContext context, Instruction instr, int pcodeop,
			Address constant, int size, RefType refType) {

		// Constant references below minSpeculative or near the end of the address space are suspect,
		// even if memory exists for those locations.
		AddressSpace space = constant.getAddressSpace();
		long maxAddrOffset = space.getMaxAddress().getOffset();
		long wordOffset = constant.getOffset();

		if (((wordOffset >= 0 && wordOffset < minSpeculativeOffset) ||
			(Math.abs(maxAddrOffset - wordOffset) < maxSpeculativeOffset)) &&
			!space.isExternalSpace()) {
			return null;
		}

		// could just be integer -1 extended into address
		if (wordOffset == 0xffffffffL || wordOffset == 0xffffL || wordOffset == -1L) {
			return null;
		}

		return constant;
	}

	/**
	 * If you override this method, and the default behavior of checking 0-256 and mask values is desired,
	 * call super.evaluateReference() in your overriden method.
	 */
	@Override
	public boolean evaluateReference(VarnodeContext context, Instruction instr, int pcodeop,
			Address address, int size, RefType refType) {

		// special check for parameters, evaluating the call, an uncomputed call wouldn't get here normally
		// really there should be another callback when adding parameters
		if (refType.isCall() && !refType.isComputed() && pcodeop == PcodeOp.UNIMPLEMENTED) {
			return true;
		}

		// unless this is a direct address copy, don't trust computed accesses below minStoreLoadOffset
		//     External spaces can have low addresses... so don't check them
		AddressSpace space = address.getAddressSpace();
		if (space.isExternalSpace()) {
			return true;
		}

		long maxAddrOffset = space.getMaxAddress().getAddressableWordOffset();
		long wordOffset = address.getAddressableWordOffset();
		boolean isKnownReference = !address.isConstantAddress();

		if (pcodeop != PcodeOp.COPY && ((wordOffset >= 0 && wordOffset < minStoreLoadOffset) ||
			(Math.abs(maxAddrOffset - wordOffset) < minStoreLoadOffset))) {
			if (!isKnownReference) {
				return false;
			}
			PcodeOp[] pcode = instr.getPcode();
			if (pcode.length > 1) { // for simple pcode, assume it is a good location.
				return false;
			}
		}

		return true;
	}

	/**
	 * Add instructions to destination set for unknown computed branches.
	 */
	@Override
	public boolean evaluateDestination(VarnodeContext context, Instruction instruction) {
		FlowType flowType = instruction.getFlowType();
		if (!flowType.isJump()) {
			return false;
		}

		/**
		 * For jump targets, that have no computed reference, add the jump location to a set
		 * to evaluate as a potential switch statement.
		 */
		Reference[] refs = instruction.getReferencesFrom();
		if (refs.length <= 0 || (refs.length == 1 && refs[0].getReferenceType().isData())) {
			destSet.addRange(instruction.getMinAddress(), instruction.getMinAddress());
		}
		return false;
	}

	/**
	 * Trust access to writable memory based on initialized option.
	 */
	@Override
	public boolean allowAccess(VarnodeContext context, Address addr) {
		return trustMemoryWrite;
	}
}
