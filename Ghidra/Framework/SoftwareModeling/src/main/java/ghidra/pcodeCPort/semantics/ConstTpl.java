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

import java.io.PrintStream;

import org.jdom.Element;

import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.FixedHandle;
import ghidra.pcodeCPort.context.ParserWalker;
import ghidra.pcodeCPort.error.LowlevelError;
import ghidra.pcodeCPort.space.AddrSpace;
import ghidra.pcodeCPort.space.spacetype;
import ghidra.pcodeCPort.translate.Translate;
import ghidra.pcodeCPort.utils.AddrSpaceToIdSymmetryMap;
import ghidra.pcodeCPort.utils.XmlUtils;

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
		j_curspace,
		j_curspace_size,
		spaceid,
		j_relative,
		j_flowref,
		j_flowref_size,
		j_flowdest,
		j_flowdest_size
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
	
	public ConstTpl(const_type tp,int ht,v_field vf,long plus) {
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

	public long fix(ParserWalker walker) {
		// Get the value of the ConstTpl in context
		// NOTE: if the property is dynamic this returns the property
		// of the temporary storage
		switch (type) {
			case j_start:
				return walker.getAddr().getOffset(); // Fill in starting address placeholder with real address
			case j_next:
				return walker.getNaddr().getOffset(); // Fill in next address placeholder with real address
			case j_curspace_size:
				return walker.getCurSpace().getAddrSize();
			case j_curspace:
				return AddrSpaceToIdSymmetryMap.getID(walker.getCurSpace());
			case handle: {
				FixedHandle hand = walker.getFixedHandle(handle_index);
				switch (select) {
					case v_space:
						if (hand.offset_space == null) {
							return AddrSpaceToIdSymmetryMap.getID(hand.space);
						}
						return AddrSpaceToIdSymmetryMap.getID(hand.temp_space);
					case v_offset:
						if (hand.offset_space == null) {
							return hand.offset_offset;
						}
						return hand.temp_offset;
					case v_size:
						return hand.size;
					case v_offset_plus:
						if (hand.space != walker.getConstSpace()) {		// If we are not a constant
							if (hand.offset_space == null) {
								return hand.offset_offset + (value_real&0xffff);
							}
							return hand.temp_offset + (value_real&0xffff);
						}
						// If we are a constant, return a shifted value
						long val;
						if (hand.offset_space == null)
							val = hand.offset_offset;
						else
							val = hand.temp_offset;
						val >>= 8 * (value_real >> 16);
						return val;
				}
				break;
			}
			case j_relative:
			case real:
				return value_real;
			case spaceid:
				return AddrSpaceToIdSymmetryMap.getID(spaceid);
			default:
				break;
		}
		return 0;			// Should never reach here
	}

	// Get the value of the ConstTpl in context
	// when we know it is a space
	public AddrSpace fixSpace(ParserWalker walker) {
		// Get the value of the ConstTpl in context
		// when we know it is a space
		switch (type) {
			case j_curspace:
				return walker.getCurSpace();
			case handle: {
				FixedHandle hand = walker.getFixedHandle(handle_index);
				switch (select) {
					case v_space:
						if (hand.offset_space == null) {
							return hand.space;
						}
						return hand.temp_space;
					default:
						break;
				}
				break;
			}
			case spaceid:
				return spaceid;
			default:
				break;
		}
		throw new LowlevelError("ConstTpl is not a spaceid as expected");
	}

	// Fill in the space portion of a FixedHandle, base on this ConstTpl
	public void fillinSpace(FixedHandle hand, ParserWalker walker) {
		switch (type) {
			case j_curspace:
				hand.space = walker.getCurSpace();
				return;
			case handle: {
				FixedHandle otherhand = walker.getFixedHandle(handle_index);
				switch (select) {
					case v_space:
						hand.space = otherhand.space;
						return;
					default:
						break;
				}
				break;
			}
			case spaceid:
				hand.space = spaceid;
				return;
			default:
				break;
		}
		throw new LowlevelError("ConstTpl is not a spaceid as expected");
	}

	// Fillin the offset portion of a FixedHandle, based on this ConstTpl
	// If the offset value is dynamic, indicate this in the handle
	// we don't just fill in the temporary variable offset
	// we assume hand.space is already filled in
	public void fillinOffset(FixedHandle hand, ParserWalker walker) {
		if (type == const_type.handle) {
			FixedHandle otherhand = walker.getFixedHandle(handle_index);
			hand.offset_space = otherhand.offset_space;
			hand.offset_offset = otherhand.offset_offset;
			hand.offset_size = otherhand.offset_size;
			hand.temp_space = otherhand.temp_space;
			hand.temp_offset = otherhand.temp_offset;
		}
		else {
			hand.offset_space = null;
			hand.offset_offset = fix(walker);
			hand.offset_offset &= hand.space.getMask();
		}
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
				if (type == const_type.real)
					value_real += (tmp & 0xffff);
				else if ((type == const_type.handle)&&(select == v_field.v_offset)) {
					select = v_field.v_offset_plus;
					value_real = tmp;
				}
				else
					throw new LowlevelError("Cannot truncate macro input in this way");
				break;
		}
	}

	private static void printHandleSelector(PrintStream s, v_field val) {
		switch (val) {
			case v_space:
				s.append("space");
				break;
			case v_offset:
				s.append("offset");
				break;
			case v_size:
				s.append("size");
				break;
			case v_offset_plus:
				s.append("offset_plus");
				break;
		}
	}

	private static v_field readHandleSelector(String name) {
		if (name.equals("space")) {
			return v_field.v_space;
		}
		if (name.equals("offset")) {
			return v_field.v_offset;
		}
		if (name.equals("size")) {
			return v_field.v_size;
		}
		if (name.equals("offset_plus")) {
			return v_field.v_offset_plus;
		}
		throw new LowlevelError("Bad handle selector");
	}

	public void changeHandleIndex(VectorSTL<Integer> handmap) {
		if (type == const_type.handle) {
			handle_index = handmap.get(handle_index);
		}
	}

	public void saveXml(PrintStream s) {
		s.append("<const_tpl type=\"");
		switch (type) {
			case real:
				s.append("real\" val=\"0x");
				s.append(Long.toHexString(value_real));
				s.append("\"/>");
				break;
			case handle:
				s.append("handle\" val=\"");
				s.print(handle_index);
				s.append("\" ");
				s.append("s=\"");
				printHandleSelector(s, select);
				s.append('\"');
				if (select == v_field.v_offset_plus)
					s.append(" plus=\"0x").append(Long.toHexString(value_real)).append('\"');
				s.append("/>");
				break;
			case j_start:
				s.append("start\"/>");
				break;
			case j_next:
				s.append("next\"/>");
				break;
			case j_curspace:
				s.append("curspace\"/>");
				break;
			case j_curspace_size:
				s.append("curspace_size\"/>");
				break;
			case spaceid:
				s.append("spaceid\" name=\"");
				s.append(spaceid.getName());
				s.append("\"/>");
				break;
			case j_relative:
				s.append("relative\" val=\"0x");
				s.append(Long.toHexString(value_real));
				s.append("\"/>");
				break;
			case j_flowref:
				s.append("flowref\"/>");
				break;
			case j_flowref_size:
				s.append("flowref_size\"/>");
				break;
			case j_flowdest:
				s.append("flowdest\"/>");
				break;
			case j_flowdest_size:
				s.append("flowdest_size\"/>");
				break;
		}
	}

	public void restoreXml(Element el, Translate trans) {
		String typestring = el.getAttributeValue("type");
		if (typestring.equals("real")) {
			type = const_type.real;
			value_real = XmlUtils.decodeUnknownLong(el.getAttributeValue("val"));
		}
		else if (typestring.equals("handle")) {
			type = const_type.handle;
			handle_index = XmlUtils.decodeUnknownInt(el.getAttributeValue("val"));
			select = readHandleSelector(el.getAttributeValue("s"));
			if (select == v_field.v_offset_plus) {
				value_real = XmlUtils.decodeUnknownLong(el.getAttributeValue("plus"));
			}
		}
		else if (typestring.equals("start")) {
			type = const_type.j_start;
		}
		else if (typestring.equals("next")) {
			type = const_type.j_next;
		}
		else if (typestring.equals("curspace")) {
			type = const_type.j_curspace;
		}
		else if (typestring.equals("curspace_size")) {
			type = const_type.j_curspace_size;
		}
		else if (typestring.equals("spaceid")) {
			type = const_type.spaceid;
			spaceid = trans.getSpaceByName(el.getAttributeValue("name"));
		}
		else if (typestring.equals("relative")) {
			type = const_type.j_relative;
			value_real = XmlUtils.decodeUnknownLong(el.getAttributeValue("val"));
		}
		else if (typestring.equals("flowref")) {
			type = const_type.j_flowref;
		}
		else if (typestring.equals("flowref_size")) {
			type = const_type.j_flowref_size;
		}
		else if (typestring.equals("flowdest")) {
			type = const_type.j_flowdest;
		}
		else if (typestring.equals("flowdest_size")) {
			type = const_type.j_flowdest_size;
		}
		else {
			throw new LowlevelError("Bad constant type");
		}
	}

}
