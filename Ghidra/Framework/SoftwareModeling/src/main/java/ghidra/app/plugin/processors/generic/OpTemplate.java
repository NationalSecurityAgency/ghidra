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
package ghidra.app.plugin.processors.generic;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

import java.io.Serializable;
import java.util.HashMap;

/**
 * 
 */
public class OpTemplate implements Serializable {
	private Operand omit;
	private VarnodeTemplate output;
	private VarnodeTemplate[] input;
	private int numInputs;
	private int opcode;
	private AddressFactory addressFactory;

	public OpTemplate(int opc, VarnodeTemplate[] in, VarnodeTemplate out, AddressFactory af) {
		opcode = opc;
		input = in;
		output = out;
		numInputs = in.length;
		addressFactory = af;
	}

	/**
	 * Method getPcode.
	 * @param handles
	 * @return PcodeOp
	 */
	public PcodeOp getPcode(HashMap<Object, Handle> handles, Position position, int opSequenceNumber, int off) throws Exception {
		int opc = opcode;

		Varnode out = null;
		if (output != null)
			out = output.resolve(handles, position, off);
		Varnode in[] = new Varnode[numInputs];
		for (int i = 0; i < numInputs; i++)
			in[i] = input[i].resolve(handles, position, off);
		
		// optimization: convert STOREs and LOADs to COPYs if possible
		if (opcode == PcodeOp.STORE) {
			Varnode ptr = in[1];
			if (ptr.isConstant()) { // if pointer is constant replace store with copy
				Varnode space = in[0];
				Varnode src = in[2];
				Address addr = addressFactory.getAddress((int)space.getOffset(),ptr.getOffset());
				out = new Varnode(addr,src.getSize());
				in = new Varnode[1];
				in[0] = src;
				opc = PcodeOp.COPY;
			}
		}
		else if (opcode == PcodeOp.LOAD) {
			Varnode ptr = in[1];
			if (ptr.isConstant()) {
				Varnode space = in[0];
				Varnode dest = out;
				Address addr = addressFactory.getAddress((int) space.getOffset(),ptr.getOffset());
				in = new Varnode[1];
				in[0] = new Varnode(addr,dest.getSize());
				opc = PcodeOp.COPY;
			}
		}
		
		// just before emitting pcode, trim constant varnodes to proper size
		for (int i = 0; i < in.length; i++)
			in[i].trim();
			
		return new PcodeOp(position.startAddr(),opSequenceNumber,opc,in,out);
	}

	public int opcode() { return opcode; }
	public VarnodeTemplate input(int i) { return input[i]; }
	public VarnodeTemplate output() { return output; }
	public void setOmit(Operand ref) { omit = ref; }


	public boolean omit() { return (omit != null && !omit.dynamic()); }

}
