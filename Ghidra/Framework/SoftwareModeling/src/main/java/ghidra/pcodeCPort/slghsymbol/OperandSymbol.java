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
package ghidra.pcodeCPort.slghsymbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.io.IOException;
import java.util.ArrayList;

import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.semantics.VarnodeTpl;
import ghidra.pcodeCPort.slghpatexpress.OperandValue;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.program.model.pcode.Encoder;
import ghidra.sleigh.grammar.Location;

public class OperandSymbol extends SpecificSymbol {

	public static final int code_address = 1;
	public static final int offset_irrel = 2;
	public static final int variable_len = 4;
	public static final int marked = 8;

	public int reloffset; // Relative offset
	public int offsetbase; // Base operand to which offset is relative (-1=constructor start)
	int minimumlength; // Minimum size of operand (within instruction tokens)
	int hand; // Handle index
	OperandValue localexp;
	private TripleSymbol triple; // Defining symbol
	private PatternExpression defexp; // OR defining expression
	private int flags;

	public OperandSymbol(Location location) {
		super(location);
	}

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

	public void setCodeAddress() {
		flags |= code_address;
	}

	public boolean isCodeAddress() {
		return ((flags & code_address) != 0);
	}

	public void setOffsetIrrelevant() {
		flags |= offset_irrel;
	}

	public boolean isOffsetIrrelevant() {
		return ((flags & offset_irrel) != 0);
	}

	public void setVariableLength() {
		flags |= variable_len;
	}

	public boolean isVariableLength() {
		return ((flags & variable_len) != 0);
	}

	public void setMark() {
		flags |= marked;
	}

	public void clearMark() {
		flags &= ~marked;
	}

	public boolean isMarked() {
		return ((flags & marked) != 0);
	}

	@Override
	public PatternExpression getPatternExpression() {
		return localexp;
	}

	@Override
	public symbol_type getType() {
		return symbol_type.operand_symbol;
	}

	public OperandSymbol(Location location, String nm, int index, Constructor ct) {
		super(location, nm);
		flags = 0;
		hand = index;
		localexp = new OperandValue(location, index, ct);
		localexp.layClaim();
		defexp = null;
		triple = null;
	}

	public void defineOperand(PatternExpression pe) {
		if ((defexp != null) || (triple != null)) {
			throw new SleighError("Redefining operand from " + pe.location, getLocation());
		}
		defexp = pe;
		defexp.layClaim();
	}

	public void defineOperand(TripleSymbol tri) {
		if ((defexp != null) || (triple != null)) {
			throw new SleighError(
				"Redefining operand " + tri.getName() + " from " + tri.getLocation(),
				getLocation());
		}
		triple = tri;
	}

	@Override
	public void dispose() {
		PatternExpression.release(localexp);
		if (defexp != null) {
			PatternExpression.release(defexp);
		}
	}

	@Override
	public VarnodeTpl getVarnode() {
		if (defexp != null) {
			return new VarnodeTpl(location, hand, true); // Definite constant handle
		}
		if (triple instanceof SpecificSymbol) {
			return ((SpecificSymbol) triple).getVarnode();
		}
		else if ((triple != null) && ((triple.getType() == symbol_type.valuemap_symbol) ||
			(triple.getType() == symbol_type.name_symbol))) {
			return new VarnodeTpl(location, hand, true); // Zero-size symbols
		}
		return new VarnodeTpl(location, hand, false); // Possible dynamic handle
	}

	@Override
	public int getSize() {
		if (triple != null) {
			return triple.getSize();
		}
		return 0;
	}

	@Override
	public void collectLocalValues(ArrayList<Long> results) {
		if (triple != null) {
			triple.collectLocalValues(results);
		}
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_OPERAND_SYM);
		encoder.writeUnsignedInteger(ATTRIB_ID, id);
		if (triple != null) {
			encoder.writeUnsignedInteger(ATTRIB_SUBSYM, triple.getId());
		}
		encoder.writeSignedInteger(ATTRIB_OFF, reloffset);
		encoder.writeSignedInteger(ATTRIB_BASE, offsetbase);
		encoder.writeSignedInteger(ATTRIB_MINLEN, minimumlength);
		if (isCodeAddress()) {
			encoder.writeBool(ATTRIB_CODE, true);
		}
		encoder.writeSignedInteger(ATTRIB_INDEX, hand);
		localexp.encode(encoder);
		if (defexp != null) {
			defexp.encode(encoder);
		}
		encoder.closeElement(ELEM_OPERAND_SYM);
	}

	@Override
	public void encodeHeader(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_OPERAND_SYM_HEAD);
		encodeSleighSymbolHeader(encoder);
		encoder.closeElement(ELEM_OPERAND_SYM_HEAD);
	}

}
