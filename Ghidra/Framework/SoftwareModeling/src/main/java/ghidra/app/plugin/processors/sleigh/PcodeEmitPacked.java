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

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.pcode.*;

/**
 * 
 *
 */
public class PcodeEmitPacked extends PcodeEmit {

	public class LabelRef {
		public int opIndex;		// Index of operation referencing the label
		public int labelIndex;	// Index of label being referenced
		public int labelSize;	// Number of bytes in the label
		public int streampos;	// Position in byte stream where label is getting encoded

		public LabelRef(int op, int lab, int size, int stream) {
			opIndex = op;
			labelIndex = lab;
			labelSize = size;
			streampos = stream;
		}
	}

	private PatchEncoder encoder;
	private ArrayList<LabelRef> labelref = null;
	private boolean hasRelativePatch = false;

	/**
	 * Pcode emitter constructor for producing a packed binary representation.
	 * @param encoder is the stream encoder to emit to
	 * @param walk parser walker
	 * @param ictx instruction contexts
	 * @param fallOffset default instruction fall offset (i.e., instruction length including delay slotted instructions)
	 * @param override required if pcode overrides are to be utilized
	 */
	public PcodeEmitPacked(PatchEncoder encoder, ParserWalker walk, InstructionContext ictx,
			int fallOffset, PcodeOverride override) {
		super(walk, ictx, fallOffset, override);
		this.encoder = encoder;
	}

	public void emitHeader() throws IOException {
		encoder.openElement(ELEM_INST);
		encoder.writeSignedInteger(ATTRIB_OFFSET, getFallOffset());
		AddressXML.encode(encoder, getStartAddress());
	}

	public void emitTail() throws IOException {
		encoder.closeElement(ELEM_INST);
	}

	@Override
	public void resolveRelatives() {
		if (labelref == null) {
			return;
		}
		for (LabelRef ref : labelref) {
			if ((ref.labelIndex >= labeldef.size()) || (labeldef.get(ref.labelIndex) == null)) {
				throw new SleighException("Reference to non-existant sleigh label");
			}
			long res = (long) labeldef.get(ref.labelIndex) - (long) ref.opIndex;
			if (ref.labelSize < 8) {
				long mask = -1;
				mask >>>= (8 - ref.labelSize) * 8;
				res &= mask;
			}
			if (!encoder.patchIntegerAttribute(ref.streampos, ATTRIB_OFFSET, res)) {
				throw new SleighException("PcodeEmitPacked: Unable to patch relative offset");
			}
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#addLabelRef()
	 */
	@Override
	void addLabelRef() {
		// We know we need to do patching on a particular input parameter
		if (labelref == null) {
			labelref = new ArrayList<>();
		}
		// Delay putting in the LabelRef until we are ready to emit the parameter
		hasRelativePatch = true;
	}

	/**
	 * Create the LabelRef now that the next element written will be the parameter needing a patch 
	 */
	private void addLabelRefDelayed() {
		int labelIndex = (int) incache[0].offset;
		int labelSize = incache[0].size;
		// Force the encoder to write out a maximum length encoding of a long
		// so that we have space to insert whatever value we need to when this relative is resolved
		incache[0].offset = -1;

		labelref.add(new LabelRef(numOps, labelIndex, labelSize, encoder.size()));
		hasRelativePatch = false;		// Mark patch as handled
	}

	@Override
	void dump(Address instrAddr, int opcode, VarnodeData[] in, int isize, VarnodeData out)
			throws IOException {
		int updatedOpcode = checkOverrides(opcode, in);
		if (opcode == PcodeOp.CALLOTHER && updatedOpcode == PcodeOp.CALL) {
			isize = 1;  //CALLOTHER_CALL_OVERRIDE, ignore inputs other than call dest
		}
		encoder.openElement(ELEM_OP);
		encoder.writeSignedInteger(ATTRIB_CODE, updatedOpcode);
		encoder.writeSignedInteger(ATTRIB_SIZE, isize);
		if (out == null) {
			encoder.openElement(ELEM_VOID);
			encoder.closeElement(ELEM_VOID);
		}
		else {
			out.encode(encoder);
		}
		int i = 0;
		if ((updatedOpcode == PcodeOp.LOAD) || (updatedOpcode == PcodeOp.STORE)) {
			dumpSpaceId(in[0]);
			i = 1;
		}
		else if (hasRelativePatch) {
			addLabelRefDelayed();
		}
		for (; i < isize; ++i) {
			in[i].encode(encoder);
		}
		encoder.closeElement(ELEM_OP);
	}

	private void dumpSpaceId(VarnodeData v) throws IOException {
		encoder.openElement(ELEM_SPACEID);
		encoder.writeSpaceId(ATTRIB_NAME, v.offset);
		encoder.closeElement(ELEM_SPACEID);
	}
}
