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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.program.model.pcode.*;

/**
 * Placeholder for what will resolve to a PcodeOp
 * for a specific InstructionContext
 */

public class OpTpl {
	private VarnodeTpl output;
	private int opcode;					// See class PcodeOp
	private VarnodeTpl[] input;

	protected OpTpl() {
	}

	public OpTpl(int opcode, VarnodeTpl output, VarnodeTpl[] inputs) {
		this.opcode = opcode;
		this.output = output;
		input = inputs;
	}

	public VarnodeTpl getOutput() {
		return output;
	}

	public VarnodeTpl[] getInput() {
		return input;
	}

	public int getOpcode() {
		return opcode;
	}

	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_OP_TPL);
		opcode = decoder.readOpcode(ATTRIB_CODE);
		int outel = decoder.peekElement();
		if (outel == ELEM_NULL.id()) {
			decoder.openElement();
			decoder.closeElement(outel);
			output = null;
		}
		else {
			output = new VarnodeTpl();
			output.decode(decoder);
		}
		ArrayList<Object> inputlist = new ArrayList<>();
		while (decoder.peekElement() != 0) {
			VarnodeTpl vn = new VarnodeTpl();
			vn.decode(decoder);
			inputlist.add(vn);
		}
		input = new VarnodeTpl[inputlist.size()];
		inputlist.toArray(input);
		decoder.closeElement(el);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		if (output != null) {
			sb.append(output);
			sb.append(" = ");
		}
		sb.append(PcodeOp.getMnemonic(opcode));
		boolean first = true;
		for (VarnodeTpl in : input) {
			if (!first) {
				sb.append(",");
			}
			first = false;
			sb.append(" ");
			sb.append(in);
		}
		return sb.toString();
	}
}
