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
package ghidra.app.plugin.processors.sleigh;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;
import ghidra.util.NumericUtilities;

/**
 * An operation on the context (bit-packed form) of an instruction
 */
public class ContextOp implements ContextChange {
	PatternExpression patexp;		// Left-hand side of context expression
	int num;						// index of word containing context var
	int mask;						// mask of variables bits within word
	int shift;						// number of bits to shift value in place

	public ContextOp() {
	}

	@Override
	public void apply(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException {
		int val = (int) patexp.getValue(walker);
		val <<= shift;
		walker.getParserContext().setContextWord(num, val, mask);
		if (debug != null) {
			debug.dumpContextSet(walker.getParserContext(), num, val, mask);
		}
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage lang) throws DecoderException {
		int el = decoder.openElement(ELEM_CONTEXT_OP);
		num = (int) decoder.readSignedInteger(ATTRIB_I);
		shift = (int) decoder.readSignedInteger(ATTRIB_SHIFT);
		mask = (int) decoder.readUnsignedInteger(ATTRIB_MASK);
		patexp = PatternExpression.decodeExpression(decoder, lang);
		decoder.closeElement(el);
	}

	public PatternExpression getPatternExpression() {
		return patexp;
	}

	public int getWordIndex() {
		return num;
	}

	public int getMask() {
		return mask;
	}

	public int getShift() {
		return shift;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("ctx&");
		for (int i = 0; i < num; i++) {
			sb.append("SS:SS:SS:SS:");
		}
		sb.append(NumericUtilities.convertMaskToHexString(mask, 8, false, 2, ":"));
		sb.append(" := ");
		sb.append(patexp);
		sb.append("( << ");
		sb.append(shift);
		sb.append(")");
		return sb.toString();
	}
}
