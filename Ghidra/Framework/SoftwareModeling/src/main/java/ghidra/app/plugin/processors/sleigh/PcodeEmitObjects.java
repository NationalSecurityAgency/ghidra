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
package ghidra.app.plugin.processors.sleigh;

import java.util.ArrayList;

import ghidra.program.model.address.*;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.pcode.*;

public class PcodeEmitObjects extends PcodeEmit {

	private ArrayList<PcodeOp> oplist;
	private ArrayList<Integer> labelref = null;

	/**
	 * Pcode emitter constructor for producing PcodeOp objects for unimplemented, snippets or empty responses
	 * when {@link #getFallOffset()} will not be used.
	 * @param walk state of the ParserContext from which to generate p-code
	 */
	public PcodeEmitObjects(ParserWalker walk) {		// For use with emitting precompiled p-code templates
		this(walk, null, 0, null, null);
	}

	/**
	 * Pcode emitter constructor for producing PcodeOp objects for unimplemented, snippets or empty responses.
	 * @param walk state of the ParserContext from which to generate p-code
	 * @param fallOffset default fall-through offset (i.e., the full length 
	 * of instruction including delay-sloted instructions)
	 */
	public PcodeEmitObjects(ParserWalker walk, int fallOffset) {		// For use with emitting precompiled p-code templates
		this(walk, null, fallOffset, null, null);
	}

	/**
	 * @param walk state of the ParserContext from which to generate p-code
	 * @param ictx is the InstructionContext used to resolve delayslot and crossbuild directives
	 * @param fallOffset default instruction fall offset (i.e., instruction length including delay slotted instructions)
	 * @param override required if pcode overrides are to be utilized
	 * @param uniqueFactory required when override specified or if overlay normalization is required
	 */
	public PcodeEmitObjects(ParserWalker walk, InstructionContext ictx, int fallOffset,
			PcodeOverride override, UniqueAddressFactory uniqueFactory) {
		super(walk, ictx, fallOffset, override, uniqueFactory);
		oplist = new ArrayList<PcodeOp>();
	}

	public PcodeOp[] getPcodeOp() {
		PcodeOp[] retop = new PcodeOp[oplist.size()];
		oplist.toArray(retop);
		return retop;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#resolveRelatives()
	 */
	@Override
	public void resolveRelatives() {
		if (labelref == null) {
			return;
		}
		for (int i = 0; i < labelref.size(); ++i) {
			int opindex = labelref.get(i);
			PcodeOp op = oplist.get(opindex);
			Varnode vn = op.getInput(0);
			int labelid = (int) vn.getOffset();
			if ((labelid >= labeldef.size()) || (labeldef.get(labelid) == null)) {
				throw new SleighException("Reference to non-existant sleigh label");
			}
			long res = (long) labeldef.get(labelid) - (long) opindex;
			if (vn.getSize() < 8) {
				long mask = -1;
				mask >>>= (8 - vn.getSize()) * 8;
				res &= mask;
			}
			AddressSpace spc = vn.getAddress().getAddressSpace();
			vn = new Varnode(spc.getAddress(res), vn.getSize());
			op.setInput(vn, 0);
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#addLabelRef()
	 */
	@Override
	void addLabelRef() {
		if (labelref == null) {
			labelref = new ArrayList<Integer>();
		}
		labelref.add(numOps);
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#dump(ghidra.program.model.address.Address, int, ghidra.app.plugin.processors.sleigh.VarnodeData[], int, ghidra.app.plugin.processors.sleigh.VarnodeData)
	 */
	@Override
	void dump(Address instrAddr, int opcode, VarnodeData[] in, int isize, VarnodeData out) {
		opcode = checkOverrides(opcode, in);
		Varnode outvn;
		if (out != null) {
			outvn = new Varnode(out.space.getAddress(out.offset), out.size);
		}
		else {
			outvn = null;
		}
		Varnode[] invn = new Varnode[isize];
		for (int i = 0; i < isize; ++i) {
			invn[i] = new Varnode(in[i].space.getAddress(in[i].offset), in[i].size);
		}
		PcodeOp op = new PcodeOp(instrAddr, oplist.size(), opcode, invn, outvn);
		oplist.add(op);
	}

}
