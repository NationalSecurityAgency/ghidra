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
import ghidra.program.model.lang.PackedBytes;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOverride;

/**
 * 
 *
 */
public class PcodeEmitPacked extends PcodeEmit {
	public final static int unimpl_tag = 0x20, inst_tag = 0x21, op_tag = 0x22, void_tag = 0x23,
			spaceid_tag = 0x24, addrsz_tag = 0x25, end_tag = 0x60;				// End of a number

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

	private PackedBytes buf;
	private ArrayList<LabelRef> labelref = null;

	/**
	 * Pcode emitter constructor for producing a packed binary representation 
	 * for unimplemented or empty responses.
	 */
	public PcodeEmitPacked() {
		super();
		buf = new PackedBytes(64);
	}

	/**
	 * Pcode emitter constructor for producing a packed binary representation.
	 * @param walk parser walker
	 * @param ictx instruction contexts
	 * @param fallOffset default instruction fall offset (i.e., instruction length including delay slotted instructions)
	 * @param override required if pcode overrides are to be utilized
	 * @param uniqueFactory required when override specified or if overlay normalization is required
	 */
	public PcodeEmitPacked(ParserWalker walk, InstructionContext ictx, int fallOffset,
			PcodeOverride override, UniqueAddressFactory uniqueFactory) {
		super(walk, ictx, fallOffset, override, uniqueFactory);
		buf = new PackedBytes(512);
	}

	public PackedBytes getPackedBytes() {
		return buf;
	}

	@Override
	public void resolveRelatives() {
		if (labelref == null) {
			return;
		}
		for (int i = 0; i < labelref.size(); ++i) {
			LabelRef ref = labelref.get(i);
			if ((ref.labelIndex >= labeldef.size()) || (labeldef.get(ref.labelIndex) == null)) {
				throw new SleighException("Reference to non-existant sleigh label");
			}
			long res = (long) labeldef.get(ref.labelIndex) - (long) ref.opIndex;
			if (ref.labelSize < 8) {
				long mask = -1;
				mask >>>= (8 - ref.labelSize) * 8;
				res &= mask;
			}
			// We need to skip over op_tag, op_code, void_tag, addrsz_tag, and spc bytes
			insertOffset(ref.streampos + 5, res);		// Insert the final offset into the stream
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#addLabelRef()
	 */
	@Override
	void addLabelRef() {
		if (labelref == null) {
			labelref = new ArrayList<LabelRef>();
		}
		int labelIndex = (int) incache[0].offset;
		int labelSize = incache[0].size;
		// Force the emitter to write out a maximum length encoding (12 bytes) of a long
		// so that we have space to insert whatever value we need to when this relative is resolved
		incache[0].offset = -1;

		labelref.add(new LabelRef(numOps, labelIndex, labelSize, buf.size()));
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.PcodeEmit#dump(ghidra.program.model.address.Address, int, ghidra.app.plugin.processors.sleigh.VarnodeData[], int, ghidra.app.plugin.processors.sleigh.VarnodeData)
	 */
	@Override
	void dump(Address instrAddr, int opcode, VarnodeData[] in, int isize, VarnodeData out) {
		opcode = checkOverrides(opcode, in);
		checkOverlays(opcode, in, isize, out);
		buf.write(op_tag);
		buf.write(opcode + 0x20);
		if (out == null) {
			buf.write(void_tag);
		}
		else {
			dumpVarnodeData(out);
		}
		int i = 0;
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			dumpSpaceId(in[0]);
			i = 1;
		}
		for (; i < isize; ++i) {
			dumpVarnodeData(in[i]);
		}
		buf.write(end_tag);
	}

	private void dumpSpaceId(VarnodeData v) {
		buf.write(spaceid_tag);
		int spcindex = ((int) v.offset >> AddressSpace.ID_UNIQUE_SHIFT);
		buf.write(spcindex + 0x20);
	}

	private void dumpVarnodeData(VarnodeData v) {
		buf.write(addrsz_tag);
		int spcindex = v.space.getUnique();
		buf.write(spcindex + 0x20);
		dumpOffset(v.offset);
		buf.write(v.size + 0x20);
	}

	public void write(int val) {
		buf.write(val);
	}

	/**
	 * Encode and dump an integer value to the packed byte stream
	 * @param val is the integer to write
	 */
	public void dumpOffset(long val) {
		while (val != 0) {
			int chunk = (int) (val & 0x3f);
			val >>>= 6;
			buf.write(chunk + 0x20);
		}
		buf.write(end_tag);
	}

	private void insertOffset(int streampos, long val) {
		while (val != 0) {
			if (buf.getByte(streampos) == end_tag) {
				throw new SleighException("Could not properly insert relative jump offset");
			}
			int chunk = (int) (val & 0x3f);
			val >>>= 6;
			buf.insertByte(streampos, chunk + 0x20);
			streampos += 1;
		}
		for (int i = 0; i < 11; ++i) {
			if (buf.getByte(streampos) == end_tag) {
				return;
			}
			buf.insertByte(streampos, 0x20);		// Zero fill
			streampos += 1;
		}
		throw new SleighException("Could not find terminator while inserting relative jump offset");
	}
}
