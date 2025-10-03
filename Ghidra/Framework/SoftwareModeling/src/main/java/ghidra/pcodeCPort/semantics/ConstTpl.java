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

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.program.model.pcode.Encoder;

public class ConstTpl {
	@Override
	public String toString() {
		return "{type=" + type + " value_real=" + String.format("0x%x", value_real) + " spaceid=" +
			spaceid + "}";
	}

	public enum const_type {
		real,
		handle,
		j_start,
		j_next,
		j_next2,
		j_curspace,
		j_curspace_size,
		spaceid,
		j_relative,
		j_flowref,
		j_flowref_size,
		j_flowdest,
		j_flowdest_size,
		j_offset
	}

	public enum v_field {
		v_space, v_offset, v_size, v_offset_plus
	}

	private const_type type;
	private AddrSpace spaceid; // Id (pointer) for registered space
	private int handle_index; // Place holder for run-time determined value
	private long value_real;
	private v_field select; // Which part of handle to use as constant

	public ConstTpl() {
		type = const_type.real;
		value_real = 0;
	}

	public ConstTpl(ConstTpl op2) {
		type = op2.type;
		spaceid = op2.spaceid;
		handle_index = op2.handle_index;
		value_real = op2.value_real;
		select = op2.select;
	}

	// Constructor for relative jump constants and uniques
	public ConstTpl(const_type tp) {
		type = tp;
	}

	// Constructor for real constants
	public ConstTpl(const_type tp, long val) {
		type = tp;
		value_real = val;
	}

	// Constructor for handle constant
	public ConstTpl(const_type tp, int ht, v_field vf) {
		type = const_type.handle;
		handle_index = ht;
		select = vf;
	}

	public ConstTpl(const_type tp, int ht, v_field vf, long plus) {
		type = const_type.handle;
		handle_index = ht;
		select = vf;
		value_real = plus;
	}

	public ConstTpl(AddrSpace sid) {
		type = const_type.spaceid;
		spaceid = sid;
	}

	public long getReal() {
		return value_real;
	}

	public AddrSpace getSpace() {
		return spaceid;
	}

	public int getHandleIndex() {
		return handle_index;
	}

	public const_type getType() {
		return type;
	}

	public v_field getSelect() {
		return select;
	}

	public boolean isZero() {
		return ((type == const_type.real) && (value_real == 0));
	}

	public boolean isConstSpace() {
		if (type == const_type.spaceid) {
			return (spaceid.getType() == spacetype.IPTR_CONSTANT);
		}
		return false;
	}

	public boolean isUniqueSpace() {
		if (type == const_type.spaceid) {
			return (spaceid.getType() == spacetype.IPTR_INTERNAL);
		}
		return false;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == this) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof ConstTpl)) {
			return false;
		}
		ConstTpl op2 = (ConstTpl) obj;
		if (type != op2.type) {
			return false;
		}
		switch (type) {
			case real:
				return (value_real == op2.value_real);
			case handle:
				if (handle_index != op2.handle_index) {
					return false;
				}
				if (select != op2.select) {
					return false;
				}
				break;
			case spaceid:
				return (spaceid == op2.spaceid);
			default: // Nothing additional to compare
				break;
		}
		return true;
	}

	public int compareTo(ConstTpl op2) {
		if (type != op2.type) {
			return type.ordinal() - op2.type.ordinal();
		}
		switch (type) {
			case real:
				long diff = value_real - op2.value_real;
				return diff < 0 ? -1 : (diff > 0 ? 1 : 0);
			case handle:
				if (handle_index != op2.handle_index) {
					return (handle_index - op2.handle_index);
				}
				return select.compareTo(op2.select);

			case spaceid:
				return (spaceid.compareTo(op2.spaceid));
			default: // Nothing additional to compare
				break;
		}
		return 0;
	}

	private void copyIntoMe(ConstTpl other) {
		type = other.type;
		spaceid = other.spaceid;
		handle_index = other.handle_index;
		value_real = other.value_real;
		select = other.select;
	}

	// Replace old handles with new handles
	public void transfer(VectorSTL<HandleTpl> params) {
		if (type != const_type.handle) {
			return;
		}
		HandleTpl newhandle = params.get(handle_index);

		switch (select) {
			case v_space:
				copyIntoMe(newhandle.getSpace());
				break;
			case v_offset:
				copyIntoMe(newhandle.getPtrOffset());
				break;
			case v_size:
				copyIntoMe(newhandle.getSize());
				break;
			case v_offset_plus:
				long tmp = value_real;
				copyIntoMe(newhandle.getPtrOffset());
				if (type == const_type.real) {
					value_real += (tmp & 0xffff);
				}
				else if ((type == const_type.handle) && (select == v_field.v_offset)) {
					select = v_field.v_offset_plus;
					value_real = tmp;
				}
				else {
					throw new LowlevelError("Cannot truncate macro input in this way");
				}
				break;
		}
	}

	public void changeHandleIndex(VectorSTL<Integer> handmap) {
		if (type == const_type.handle) {
			handle_index = handmap.get(handle_index);
		}
	}

	public void encode(Encoder encoder) throws IOException {
		switch (type) {
			case real:
				encoder.openElement(ELEM_CONST_REAL);
				encoder.writeUnsignedInteger(ATTRIB_VAL, value_real);
				encoder.closeElement(ELEM_CONST_REAL);
				break;
			case handle:
				encoder.openElement(ELEM_CONST_HANDLE);
				encoder.writeSignedInteger(ATTRIB_VAL, handle_index);
				encoder.writeSignedInteger(ATTRIB_S, select.ordinal());
				if (select == v_field.v_offset_plus) {
					encoder.writeUnsignedInteger(ATTRIB_PLUS, value_real);
				}
				encoder.closeElement(ELEM_CONST_HANDLE);
				break;
			case j_start:
				encoder.openElement(ELEM_CONST_START);
				encoder.closeElement(ELEM_CONST_START);
				break;
			case j_offset:
				encoder.openElement(ELEM_CONST_OFFSET);
				encoder.closeElement(ELEM_CONST_OFFSET);
				break;
			case j_next:
				encoder.openElement(ELEM_CONST_NEXT);
				encoder.closeElement(ELEM_CONST_NEXT);
				break;
			case j_next2:
				encoder.openElement(ELEM_CONST_NEXT2);
				encoder.closeElement(ELEM_CONST_NEXT2);
				break;
			case j_curspace:
				encoder.openElement(ELEM_CONST_CURSPACE);
				encoder.closeElement(ELEM_CONST_CURSPACE);
				break;
			case j_curspace_size:
				encoder.openElement(ELEM_CONST_CURSPACE_SIZE);
				encoder.closeElement(ELEM_CONST_CURSPACE_SIZE);
				break;
			case spaceid:
				encoder.openElement(ELEM_CONST_SPACEID);
				encoder.writeSpace(ATTRIB_SPACE, spaceid.getIndex(), spaceid.getName());
				encoder.closeElement(ELEM_CONST_SPACEID);
				break;
			case j_relative:
				encoder.openElement(ELEM_CONST_RELATIVE);
				encoder.writeUnsignedInteger(ATTRIB_VAL, value_real);
				encoder.closeElement(ELEM_CONST_RELATIVE);
				break;
			case j_flowref:
				encoder.openElement(ELEM_CONST_FLOWREF);
				encoder.closeElement(ELEM_CONST_FLOWREF);
				break;
			case j_flowref_size:
				encoder.openElement(ELEM_CONST_FLOWREF_SIZE);
				encoder.closeElement(ELEM_CONST_FLOWREF_SIZE);
				break;
			case j_flowdest:
				encoder.openElement(ELEM_CONST_FLOWDEST);
				encoder.closeElement(ELEM_CONST_FLOWDEST);
				break;
			case j_flowdest_size:
				encoder.openElement(ELEM_CONST_FLOWDEST_SIZE);
				encoder.closeElement(ELEM_CONST_FLOWDEST_SIZE);
				break;
		}
	}
}
