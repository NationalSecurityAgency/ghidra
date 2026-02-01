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
 * Created on Feb 8, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.OperandValue;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Variable representing an operand to a specific Constructor
 */
public class OperandSymbol extends SpecificSymbol {

	private int reloffset;		// Relative offset
	// NOTE: Additional offset, specified in bytes (to the right)
	private int offsetbase;		// Base operand to which offset is relative
	// NOTE: Relative to the end of the specified operand, given by index
	private int minimumlength;	// Minimum size of operand (within tokens)
	private int hand;			// Index of this operand in constructor
	private OperandValue localexp;
	private TripleSymbol triple;	// Defining symbol
	private PatternExpression defexp;	// OR defining expression
	private boolean codeaddress;	// true if the operand is used as an address

	public int getRelativeOffset() {
		return reloffset;
	}

	public int getOffsetBase() {
		return offsetbase;
	}

	public int getMinimumLength() {
		return minimumlength;
	}

	public PatternExpression getDefiningExpression() {
		return defexp;
	}

	public TripleSymbol getDefiningSymbol() {
		return triple;
	}

	public int getIndex() {
		return hand;
	}

	public boolean isCodeAddress() {
		return codeaddress;
	}

	@Override
	public PatternExpression getPatternExpression() {
		return localexp;
	}

	@Override
	public void getFixedHandle(FixedHandle hnd, ParserWalker walker) {
		FixedHandle h = walker.getFixedHandle(hand);
		hnd.space = h.space;
		hnd.offset_space = h.offset_space;
		hnd.offset_offset = h.offset_offset;
		hnd.offset_size = h.offset_size;
		hnd.size = h.size;
		hnd.temp_space = h.temp_space;
		hnd.temp_offset = h.temp_offset;
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		String res;
		walker.pushOperand(hand);
		if (triple != null) {
			if (triple instanceof SubtableSymbol) {
				res = walker.getConstructor().print(walker);
			}
			else {
				res = triple.print(walker);
			}
		}
		else {		// Must be expression resulting in a constant
			long val = defexp.getValue(walker);
			if (val >= 0) {
				res = "0x" + Long.toHexString(val);
			}
			else {
				res = "-0x" + Long.toHexString(-val);
			}
		}
		walker.popOperand();
		return res;
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list)
			throws MemoryAccessException {
		walker.pushOperand(hand);
		if (triple != null) {
			if (triple instanceof SubtableSymbol) {
				walker.getConstructor().printList(walker, list);
			}
			else {
				triple.printList(walker, list);
			}
		}
		else {
			FixedHandle handle = walker.getParentHandle();
			if (handle.offset_size == 0) {
				handle.offset_size = walker.getCurrentLength();
			}
			list.add(handle);
		}
		walker.popOperand();
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
//		int el = decoder.openElement(ELEM_OPERAND_SYM);
		defexp = null;
		triple = null;
		codeaddress = false;
		int attrib = decoder.getNextAttributeId();
		while (attrib != 0) {
			if (attrib == ATTRIB_INDEX.id()) {
				hand = (int) decoder.readSignedInteger();
			}
			else if (attrib == ATTRIB_OFF.id()) {
				reloffset = (int) decoder.readSignedInteger();
			}
			else if (attrib == ATTRIB_BASE.id()) {
				offsetbase = (int) decoder.readSignedInteger();
			}
			else if (attrib == ATTRIB_MINLEN.id()) {
				minimumlength = (int) decoder.readSignedInteger();
			}
			else if (attrib == ATTRIB_SUBSYM.id()) {
				int id = (int) decoder.readUnsignedInteger();
				triple = (TripleSymbol) lang.getSymbolTable().findSymbol(id);
			}
			else if (attrib == ATTRIB_CODE.id()) {
				codeaddress = decoder.readBool();
			}
			attrib = decoder.getNextAttributeId();
		}

		localexp = (OperandValue) PatternExpression.decodeExpression(decoder, lang);
		if (decoder.peekElement() != 0) {
			defexp = PatternExpression.decodeExpression(decoder, lang);
		}
		decoder.closeElement(ELEM_OPERAND_SYM.id());
	}

	@Override
	public String toString() {
		return this.getName() + " : " + this.getId();
	}
}
