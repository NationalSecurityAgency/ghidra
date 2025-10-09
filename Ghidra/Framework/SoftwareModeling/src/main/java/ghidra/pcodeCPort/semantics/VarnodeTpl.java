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
package ghidra.pcodeCPort.semantics;

import static ghidra.pcode.utils.SlaFormat.ELEM_VARNODE_TPL;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.semantics.ConstTpl.const_type;
import ghidra.pcodeCPort.semantics.ConstTpl.v_field;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class VarnodeTpl {
	public final Location location;

	private ConstTpl space;
	private ConstTpl offset;
	private ConstTpl size;
	boolean unnamed_flag;

	public void dispose() {

	}

	public ConstTpl getSpace() {
		return space;
	}

	public ConstTpl getOffset() {
		return offset;
	}

	public ConstTpl getSize() {
		return size;
	}

	public boolean isZeroSize() {
		return size.isZero();
	}

	public void setOffset(long constVal) {
		offset = new ConstTpl(ConstTpl.const_type.real, constVal);
	}

	public void setRelative(long constVal) {
		offset = new ConstTpl(ConstTpl.const_type.j_relative, constVal);
	}

	public void setSize(ConstTpl sz) {
		size = new ConstTpl(sz);
	}

	public boolean isUnnamed() {
		return unnamed_flag;
	}

	public void setUnnamed(boolean val) {
		unnamed_flag = val;
	}

	public boolean isRelative() {
		return (offset.getType() == ConstTpl.const_type.j_relative);
	}

	public VarnodeTpl(Location location, int hand, boolean zerosize) {
		this.location = location;
		space = new ConstTpl(ConstTpl.const_type.handle, hand, ConstTpl.v_field.v_space);
		offset = new ConstTpl(ConstTpl.const_type.handle, hand, ConstTpl.v_field.v_offset);
		size = new ConstTpl(ConstTpl.const_type.handle, hand, ConstTpl.v_field.v_size);
		// Varnode built from a handle
		// if zerosize is true, set the size constant to zero
		if (zerosize) {
			size = new ConstTpl(ConstTpl.const_type.real, 0);
		}
		unnamed_flag = false;
	}

	public VarnodeTpl(Location location, ConstTpl sp, ConstTpl off, ConstTpl sz) {
		this.location = location;
		space = new ConstTpl(sp);
		offset = new ConstTpl(off);
		size = new ConstTpl(sz);
		unnamed_flag = false;
	}

	public VarnodeTpl(Location location, VarnodeTpl vn) {
		this.location = location;
		space = new ConstTpl(vn.space);
		offset = new ConstTpl(vn.offset);
		size = new ConstTpl(vn.size);
		// A clone of the VarnodeTpl
		unnamed_flag = vn.unnamed_flag;
	}

	public VarnodeTpl(Location location) {
		this.location = location;
		unnamed_flag = false;
		space = new ConstTpl();
		offset = new ConstTpl();
		size = new ConstTpl();
	}

	public boolean isLocalTemp() {
		if (space.getType() != ConstTpl.const_type.spaceid) {
			return false;
		}
		if (space.getSpace().getType() != spacetype.IPTR_INTERNAL) {
			return false;
		}
		return true;
	}

	public int transfer(VectorSTL<HandleTpl> params) {
		boolean doesOffsetPlus = false;
		int handleIndex = 0;
		int plus = 0;

		if ((offset.getType() == const_type.handle) &&
			(offset.getSelect() == v_field.v_offset_plus)) {
			handleIndex = offset.getHandleIndex();
			plus = (int) offset.getReal();
			doesOffsetPlus = true;
		}
		space.transfer(params);
		offset.transfer(params);
		size.transfer(params);
		if (doesOffsetPlus) {
			if (isLocalTemp()) {
				return plus;		// A positive number indicates truncation of a local temp
			}
			if (params.get(handleIndex).getSize().isZero()) {
				return plus;		//     or a zerosize object
			}
		}
		return -1;
	}

	public void changeHandleIndex(VectorSTL<Integer> handmap) {
		space.changeHandleIndex(handmap);
		offset.changeHandleIndex(handmap);
		size.changeHandleIndex(handmap);
	}

	public boolean adjustTruncation(int sz, boolean isbigendian) {
		// We know this.offset is an v_field.offset_plus, check that the truncation is in bounds (given -sz-)
		// adjust plus for endianness if necessary
		// return true if truncation is in bounds
		if (size.getType() != const_type.real) {
			return false;
		}
		int numbytes = (int) size.getReal();
		int byteoffset = (int) offset.getReal();
		if (numbytes + byteoffset > sz) {
			return false;
		}

		// Encode the original truncation amount with the plus value
		long val = byteoffset;
		val <<= 16;
		if (isbigendian) {
			val |= (sz - (numbytes + byteoffset));
		}
		else {
			val |= byteoffset;
		}

		offset =
			new ConstTpl(const_type.handle, offset.getHandleIndex(), v_field.v_offset_plus, val);
		return true;
	}

	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_VARNODE_TPL);
		space.encode(encoder);
		offset.encode(encoder);
		size.encode(encoder);
		encoder.closeElement(ELEM_VARNODE_TPL);
	}

	public int compareTo(VarnodeTpl op2) {
		int result = space.compareTo(op2.space);
		if (result != 0) {
			return result;
		}
		result = offset.compareTo(op2.offset);
		if (result != 0) {
			return result;
		}
		return size.compareTo(op2.size);
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (!(obj instanceof VarnodeTpl op2)) {
			return false;
		}
		return space.equals(op2.space) && offset.equals(op2.offset) && size.equals(op2.size);
	}

	@Override
	public String toString() {
		return "[space=%s:offset=%s:size=%s]".formatted(space, offset, size);
	}
}
