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
package ghidra.app.plugin.processors.sleigh.expression;

import static ghidra.pcode.utils.SlaFormat.*;

import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * An expression which results in a pattern for a specific InstructionContext
 */
public abstract class PatternExpression {
	public abstract long getValue(ParserWalker walker) throws MemoryAccessException;

	public abstract void decode(Decoder decoder, SleighLanguage lang) throws DecoderException;

	public static PatternExpression decodeExpression(Decoder decoder, SleighLanguage lang)
			throws DecoderException {
		int el = decoder.peekElement();
		PatternExpression res;
		if (el == ELEM_TOKENFIELD.id()) {
			res = new TokenField();
		}
		else if (el == ELEM_CONTEXTFIELD.id()) {
			res = new ContextField();
		}
		else if (el == ELEM_INTB.id()) {
			res = new ConstantValue();
		}
		else if (el == ELEM_OPERAND_EXP.id()) {
			res = new OperandValue();
		}
		else if (el == ELEM_START_EXP.id()) {
			res = new StartInstructionValue();
		}
		else if (el == ELEM_END_EXP.id()) {
			res = new EndInstructionValue();
		}
		else if (el == ELEM_NEXT2_EXP.id()) {
			res = new Next2InstructionValue();
		}
		else if (el == ELEM_PLUS_EXP.id()) {
			res = new PlusExpression();
		}
		else if (el == ELEM_SUB_EXP.id()) {
			res = new SubExpression();
		}
		else if (el == ELEM_MULT_EXP.id()) {
			res = new MultExpression();
		}
		else if (el == ELEM_LSHIFT_EXP.id()) {
			res = new LeftShiftExpression();
		}
		else if (el == ELEM_RSHIFT_EXP.id()) {
			res = new RightShiftExpression();
		}
		else if (el == ELEM_AND_EXP.id()) {
			res = new AndExpression();
		}
		else if (el == ELEM_OR_EXP.id()) {
			res = new OrExpression();
		}
		else if (el == ELEM_XOR_EXP.id()) {
			res = new XorExpression();
		}
		else if (el == ELEM_DIV_EXP.id()) {
			res = new DivExpression();
		}
		else if (el == ELEM_MINUS_EXP.id()) {
			res = new MinusExpression();
		}
		else if (el == ELEM_NOT_EXP.id()) {
			res = new NotExpression();
		}
		else {
			return null;
		}

		res.decode(decoder, lang);
		return res;
	}

	@Override
	public abstract String toString();
}
