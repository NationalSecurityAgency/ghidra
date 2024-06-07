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

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InstructionContext;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Placeholder that resolves for a specific {@link InstructionContext} into a {@link FixedHandle}
 * representing the semantic value of a {@link Constructor}
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

	public HandleTpl(ConstTpl spc, ConstTpl sz, ConstTpl ptrspc, ConstTpl ptroff, ConstTpl ptrsz,
			ConstTpl tmpspc, ConstTpl tmpoff) {
		space = spc;
		size = sz;
		ptrspace = ptrspc;
		ptroffset = ptroff;
		ptrsize = ptrsz;
		temp_space = tmpspc;
		temp_offset = tmpoff;
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
		if (!hand.fixable) {
			return;
		}
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

	public void decode(Decoder decoder) throws DecoderException {
		int el = decoder.openElement(ELEM_HANDLE_TPL);
		space = new ConstTpl();
		space.decode(decoder);
		size = new ConstTpl();
		size.decode(decoder);
		ptrspace = new ConstTpl();
		ptrspace.decode(decoder);
		ptroffset = new ConstTpl();
		ptroffset.decode(decoder);
		ptrsize = new ConstTpl();
		ptrsize.decode(decoder);
		temp_space = new ConstTpl();
		temp_space.decode(decoder);
		temp_offset = new ConstTpl();
		temp_offset.decode(decoder);
		decoder.closeElement(el);
	}

	public int getOffsetOperandIndex() {
		return ptroffset.getHandleIndex();
	}

	/**
	 * Get the size of the expected value in bits
	 * 
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

	/**
	 * Get the address space of the value, if applicable
	 * 
	 * @return the address space, or null if not applicable
	 */
	public AddressSpace getAddressSpace() {
		return space.getSpaceId();
	}
}
