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
 * Created on Feb 3, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.template;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A placeholder for what will resolve to a field of a Varnode
 * (an AddressSpace or integer offset or integer size)
 * given a particular InstructionContext
 */
public class ConstTpl {

	public static final int REAL = 0;
	public static final int HANDLE = 1;
	public static final int J_START = 2;
	public static final int J_NEXT = 3;
	public static final int J_CURSPACE = 4;
	public static final int J_CURSPACE_SIZE = 5;
	public static final int SPACEID = 6;
	public static final int J_RELATIVE = 7;
	public static final int J_FLOWREF = 8;
	public static final int J_FLOWREF_SIZE = 9;
	public static final int J_FLOWDEST = 10;
	public static final int J_FLOWDEST_SIZE = 11;

	public static final int V_SPACE = 0;
	public static final int V_OFFSET = 1;
	public static final int V_SIZE = 2;
	public static final int V_OFFSET_PLUS = 3;

	public static final long[] calc_mask = { 0, 0xffL, 0xffffL, 0xffffffL, 0xffffffffL,
		0xffffffffffL, 0xffffffffffffL, 0xffffffffffffffL, 0xffffffffffffffffL };

	private int type;
	private long value_real;
	private AddressSpace value_spaceid;
	private short handle_index;
	private short select;		// Which part of handle to use as constant

	protected ConstTpl() {
		type = REAL;
		value_real = 0;
	}

	public ConstTpl(ConstTpl op2) {
		type = op2.type;
		value_real = op2.value_real;
		value_spaceid = op2.value_spaceid;
		handle_index = op2.handle_index;
		select = op2.select;
	}

	public ConstTpl(int tp, long val) {
		type = tp;
		value_real = val;
	}

	public ConstTpl(int tp) {
		type = tp;
	}

	public ConstTpl(AddressSpace spc) {
		type = SPACEID;
		value_spaceid = spc;
	}

	public ConstTpl(int tp, int ht, int vf) {
		type = HANDLE;
		handle_index = (short) ht;
		select = (short) vf;
	}

	public boolean isConstSpace() {
		if (type == SPACEID) {
			return (value_spaceid.getType() == AddressSpace.TYPE_CONSTANT);
		}
		return false;
	}

	public boolean isUniqueSpace() {
		if (type == SPACEID) {
			return (value_spaceid.getType() == AddressSpace.TYPE_UNIQUE);
		}
		return false;
	}

	public long getReal() {
		return value_real;
	}

	public AddressSpace getSpaceId() {
		return value_spaceid;
	}

	public int getHandleIndex() {
		return handle_index;
	}

	public int getType() {
		return type;
	}

	public long fix(ParserWalker walker) {
		switch (type) {
			case J_START:
				return walker.getAddr().getOffset();
			case J_NEXT:
				return walker.getNaddr().getOffset();
			case J_FLOWREF:
				return walker.getFlowRefAddr().getOffset();
			case J_FLOWREF_SIZE:
				return walker.getFlowRefAddr().getAddressSpace().getPointerSize();
			case J_FLOWDEST:
				return walker.getFlowDestAddr().getOffset();
			case J_FLOWDEST_SIZE:
				return walker.getFlowDestAddr().getAddressSpace().getPointerSize();
			case J_CURSPACE_SIZE:
				return walker.getCurSpace().getPointerSize();
			case J_CURSPACE:
				return walker.getCurSpace().getSpaceID();
			case HANDLE: {
				FixedHandle hand = walker.getFixedHandle(handle_index);
				switch (select) {
					case V_SPACE:
						if (hand.offset_space == null) {
							return hand.space.getSpaceID();
						}
						return hand.temp_space.getSpaceID();
					case V_OFFSET:
						if (hand.offset_space == null) {
							return hand.offset_offset;
						}
						return hand.temp_offset;
					case V_SIZE:
						return hand.size;
					case V_OFFSET_PLUS:
						if (hand.space.getType() != AddressSpace.TYPE_CONSTANT) {	// If we are not a constant
							if (hand.offset_space == null)
							 {
								return hand.offset_offset + (value_real & 0xffff);		// Adjust offset by truncation amount
							}
							return hand.temp_offset + (value_real & 0xffff);
						}
						// If we are a constant, shift by the truncation amount
						long val;
						if (hand.offset_space == null) {
							val = hand.offset_offset;
						}
						else {
							val = hand.temp_offset;
						}
						val >>= 8 * (value_real >> 16);
						return val;
				}
				break;
			}
			case J_RELATIVE:
			case REAL:
				return value_real;
			case SPACEID:
				return value_spaceid.getSpaceID();
		}
		return 0;			// Should never reach here
	}

	public AddressSpace fixSpace(ParserWalker walker) throws SleighException {
		switch (type) {
			case J_CURSPACE:
				return walker.getCurSpace();
			case HANDLE: {
				FixedHandle hand = walker.getFixedHandle(handle_index);
				switch (select) {
					case V_SPACE:
						if (hand.offset_space == null) {
							return hand.space;
						}
						return hand.temp_space;
					default:
						break;
				}
				break;
			}
			case SPACEID:
				return value_spaceid;
			case J_FLOWREF:
				return walker.getFlowRefAddr().getAddressSpace();
			default:
				break;
		}
		throw new SleighException("ConstTpl is not a spaceid as expected");
	}

	/**
	 * Fill in the space portion of a FixedHandle, based
	 * on this const.
	 * @param hand handle to fillin
	 * @param walker current parser walker
	 */
	public void fillinSpace(FixedHandle hand, ParserWalker walker) {
		switch (type) {
			case J_CURSPACE:
				hand.space = walker.getCurSpace();
				return;
			case HANDLE: {
				FixedHandle otherhand = walker.getFixedHandle(handle_index);
				switch (select) {
					case V_SPACE:
						hand.space = otherhand.space;
						return;
					default:
						break;
				}
			}
			case SPACEID:
				hand.space = value_spaceid;
				return;
			default:
				break;
		}
		throw new SleighException("ConstTpl is not a spaceid as expected");
	}

	/**
	 * Fillin the offset portion of a FixedHandle based on this
	 * const. If the offset value is dynamic, fill in the handle
	 * appropriately.  We don't just fill in the temporary
	 * variable offset, like "fix". Assume that hand.space is
	 * already filled in
	 * @param hand handle to fillin
	 * @param walker current parser walker
	 */
	public void fillinOffset(FixedHandle hand, ParserWalker walker) {
		if (type == HANDLE) {
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
			hand.offset_offset = hand.space.truncateOffset(hand.offset_offset);
		}
	}

	public void restoreXml(XmlPullParser parser, AddressFactory factory) {
		XmlElement el = parser.start("const_tpl");
		String typestr = el.getAttribute("type");
		if (typestr.equals("real")) {
			type = REAL;
			value_real = SpecXmlUtils.decodeLong(el.getAttribute("val"));
		}
		else if (typestr.equals("handle")) {
			type = HANDLE;
			handle_index = (short) SpecXmlUtils.decodeInt(el.getAttribute("val"));
			String selstr = el.getAttribute("s");
			if (selstr.equals("space")) {
				select = V_SPACE;
			}
			else if (selstr.equals("offset")) {
				select = V_OFFSET;
			}
			else if (selstr.equals("size")) {
				select = V_SIZE;
			}
			else if (selstr.equals("offset_plus")) {
				select = V_OFFSET_PLUS;
				value_real = SpecXmlUtils.decodeLong(el.getAttribute("plus"));
			}
			else {
				throw new SleighException("Bad handle selector");
			}
		}
		else if (typestr.equals("start")) {
			type = J_START;
		}
		else if (typestr.equals("next")) {
			type = J_NEXT;
		}
		else if (typestr.equals("curspace")) {
			type = J_CURSPACE;
		}
		else if (typestr.equals("curspace_size")) {
			type = J_CURSPACE_SIZE;
		}
		else if (typestr.equals("spaceid")) {
			type = SPACEID;
			value_spaceid = factory.getAddressSpace(el.getAttribute("name"));
		}
		else if (typestr.equals("relative")) {
			type = J_RELATIVE;
			value_real = SpecXmlUtils.decodeLong(el.getAttribute("val"));
		}
		else if (typestr.equals("flowref")) {
			type = J_FLOWREF;
		}
		else if (typestr.equals("flowref_size")) {
			type = J_FLOWREF_SIZE;
		}
		else if (typestr.equals("flowdest")) {
			type = J_FLOWDEST;
		}
		else if (typestr.equals("flowdest_size")) {
			type = J_FLOWDEST_SIZE;
		}
		else {
			throw new SleighException("Bad xml for ConstTpl");
		}
		parser.end(el);
	}

	@Override
	public String toString() {
		switch (type) {
			case SPACEID:
				return value_spaceid.getName();
			case REAL:
				return Long.toHexString(value_real);
			case HANDLE:
				switch (select) {
					case V_SPACE:
						return "[handle:space]";
					case V_SIZE:
						return "[handle:size]";
					case V_OFFSET:
						return "[handle:offset]";
					case V_OFFSET_PLUS:
						return "[handle:offset+" + Long.toHexString(value_real) + "]";
				}
			case J_CURSPACE:
				return "[curspace]";
			case J_CURSPACE_SIZE:
				return "[curspace_size]";
			case J_FLOWDEST:
				return "[flowdest]";
			case J_FLOWDEST_SIZE:
				return "[flowdest_size]";
			case J_FLOWREF:
				return "[flowref]";
			case J_FLOWREF_SIZE:
				return "[flowref_size]";
			case J_NEXT:
				return "[next]";
			case J_START:
				return "[start]";
			case J_RELATIVE:
				return "[rel:" + Long.toHexString(value_real) + "]";
		}
		throw new RuntimeException("This should be unreachable");
	}
}
