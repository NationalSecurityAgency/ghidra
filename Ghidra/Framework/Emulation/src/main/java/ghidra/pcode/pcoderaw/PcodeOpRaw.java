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
package ghidra.pcode.pcoderaw;

import ghidra.pcode.opbehavior.OpBehavior;
import ghidra.pcode.opbehavior.OpBehaviorFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;

public class PcodeOpRaw extends PcodeOp {

	private OpBehavior behave;

	public PcodeOpRaw(PcodeOp op) {
		super(op.getSeqnum(), op.getOpcode(), op.getInputs(), op.getOutput());
		behave = OpBehaviorFactory.getOpBehavior(op.getOpcode());
	}

	// Get the underlying behavior object for this pcode operation.  From this
	// object you can determine how the object evaluates inputs to get the output
	// \return the behavior object
	public OpBehavior getBehavior() {
		return behave;
	}

	// This is a convenience function to get the address of the machine instruction
	// (of which this pcode op is a translation)
	// \return the machine instruction address
	public Address getAddress() {
		return getSeqnum().getTarget();
	}
}
