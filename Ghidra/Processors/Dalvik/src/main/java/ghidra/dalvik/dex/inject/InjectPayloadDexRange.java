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
package ghidra.dalvik.dex.inject;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Implements the DEX userop 'moveRangeToIV'
 * The first input should be a constant indicating the number of registers to move
 * The second input is the offset (in register space) of the first register to move.
 * The registers are moved to the specially designated input registers iv0, iv1, iv2, ...
 *
 */
public class InjectPayloadDexRange extends InjectPayloadCallother {

	public InjectPayloadDexRange() {
		super("dexrange");
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		if (con.inputlist.size() != 2) {
			return null;			// Error
		}
		// The first Varnode must be a constant specifying the number of parameters
		int numParams = (int) con.inputlist.get(0).getOffset();
		// The second Varnode must be the first register to be moved
		long fromOffset = con.inputlist.get(1).getOffset();
		// Base of designated input registers
		long toOffset = InjectPayloadDexParameters.INPUT_REGISTER_START;
		AddressSpace registerSpace = program.getAddressFactory().getAddressSpace("register");
		PcodeOp[] resOps = new PcodeOp[numParams];
		for (int i = 0; i < numParams; ++i) {
			Address fromAddr = registerSpace.getAddress(fromOffset);
			Address toAddr = registerSpace.getAddress(toOffset);
			fromOffset += 4;
			toOffset += 4;
			PcodeOp op = new PcodeOp(con.baseAddr, i, PcodeOp.COPY);
			op.setInput(new Varnode(fromAddr, 4), 0);
			op.setOutput(new Varnode(toAddr, 4));
			resOps[i] = op;
		}
		return resOps;
	}
}
