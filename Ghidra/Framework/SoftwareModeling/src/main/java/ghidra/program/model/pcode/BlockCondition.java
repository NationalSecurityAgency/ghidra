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
package ghidra.program.model.pcode;

import java.io.IOException;

import ghidra.program.model.lang.UnknownInstructionException;

/**
 * Block representing and '&amp;&amp;' or '||' control flow path within a conditional expression
 *     possible multiple incoming edges
 *     2 outgoing edges,  one for true control flow, one for false control flow
 *     
 *     one "initial" condition block, with 2 outgoing edges
 *     one "secondary" condition block, with 2 outgoing edges, exactly 1 incoming edge from "initial"
 *
 */
public class BlockCondition extends BlockGraph {
	private int opcode;			// Type of boolean operation

	public BlockCondition() {
		super();
		blocktype = PcodeBlock.CONDITION;
		opcode = PcodeOp.BOOL_AND;
	}

	public int getOpcode() {
		return opcode;
	}

	@Override
	protected void encodeHeader(Encoder encoder) throws IOException {
		super.encodeHeader(encoder);
		String opcodename = PcodeOp.getMnemonic(opcode);
		encoder.writeString(AttributeId.ATTRIB_OPCODE, opcodename);
	}

	@Override
	protected void decodeHeader(Decoder decoder) throws PcodeXMLException {
		super.decodeHeader(decoder);
		String opcodename = decoder.readString(AttributeId.ATTRIB_OPCODE);
		try {
			opcode = PcodeOp.getOpcode(opcodename);
		}
		catch (UnknownInstructionException e) {
			opcode = PcodeOp.BOOL_AND;
		}
	}
}
