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

import ghidra.app.plugin.processors.sleigh.FixedHandle;
import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 *  Placeholder that resolves for a specific InstructionContext into 
 *  a FixedHandle representing the semantic value of a Constructor 
 */
public class HandleTpl {

	private ConstTpl space;
	private ConstTpl size;
	private ConstTpl ptrspace;
	private ConstTpl ptroffset;
	private ConstTpl ptrsize;
	private ConstTpl temp_space;
	private ConstTpl temp_offset;

	protected HandleTpl() {
	}

	public void fix(FixedHandle hand, ParserWalker walker) {
		if (ptrspace.getType() == ConstTpl.REAL) {
			// The export is unstarred, but this doesn't mean
			// the varnode being exported isn't dynamic
			space.fillinSpace(hand, walker);
			hand.size = (int) size.fix(walker);
			ptroffset.fillinOffset(hand, walker);
		}
		else {
			hand.space = space.fixSpace(walker);
			hand.size = (int) size.fix(walker);
			hand.offset_offset = ptroffset.fix(walker);
			hand.offset_space = ptrspace.fixSpace(walker);
			if (hand.offset_space.getType() == AddressSpace.TYPE_CONSTANT) {
				hand.offset_space = null;	// Could have been, but wasn't
				hand.offset_offset *= hand.space.getAddressableUnitSize();
				hand.offset_offset = hand.space.truncateOffset(hand.offset_offset);
			}
			else {
				hand.offset_size = (int) ptrsize.fix(walker);
				hand.temp_space = temp_space.fixSpace(walker);
				hand.temp_offset = temp_offset.fix(walker);
			}
		}
	}

	public void fixPrintPiece(FixedHandle hand, ParserWalker walker, int handleIndex) {
		if (!hand.fixable)
			return;
		if (hand.space.getType() != AddressSpace.TYPE_CONSTANT) {
			hand.fixable = false;
			return;
		}
		if (space.getType() == ConstTpl.SPACEID) {
			if (space.isUniqueSpace()) {
				hand.fixable = false;
				return;
			}
		}
		if (ptroffset.getType() == ConstTpl.HANDLE && ptroffset.getHandleIndex() == handleIndex) {
			hand.space = space.fixSpace(walker);
			hand.offset_offset = hand.space.getAddressableUnitSize() * hand.offset_offset;
			hand.size = (int) size.fix(walker);
		}
		else {
			hand.fixable = false;
		}
	}

	public void restoreXml(XmlPullParser parser, AddressFactory factory) {
		XmlElement el = parser.start("handle_tpl");
		space = new ConstTpl();
		space.restoreXml(parser, factory);
		size = new ConstTpl();
		size.restoreXml(parser, factory);
		ptrspace = new ConstTpl();
		ptrspace.restoreXml(parser, factory);
		ptroffset = new ConstTpl();
		ptroffset.restoreXml(parser, factory);
		ptrsize = new ConstTpl();
		ptrsize.restoreXml(parser, factory);
		temp_space = new ConstTpl();
		temp_space.restoreXml(parser, factory);
		temp_offset = new ConstTpl();
		temp_offset.restoreXml(parser, factory);
		parser.end(el);
	}

	public int getOffsetOperandIndex() {
		return ptroffset.getHandleIndex();
	}

	/**
	 * Get the size of the expected value in bits
	 * @return the number of bits
	 */
	public int getSize() {
		if (space.isConstSpace()) {
			return (int) size.getReal() * 8;
		}
		else if (space.getSpaceId() == null) {
			return 0;
		}
		else {
			return space.getSpaceId().getSize();
		}
	}
}
