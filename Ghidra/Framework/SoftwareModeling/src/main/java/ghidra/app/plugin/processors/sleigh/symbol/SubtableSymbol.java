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
 * Created on Feb 9, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * A collection of Constructors or a Symbol representing
 * one out of a family of Constructors, choosen based on InstructionContext
 */
public class SubtableSymbol extends TripleSymbol {

	private Constructor[] construct;	// All the constructors in this table
	private DecisionNode decisiontree;	// The decision tree for this table

	public DecisionNode getDecisionNode() {
		return decisiontree;
	}

	@Override
	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		return decisiontree.resolve(walker, debug);
	}

	public int getNumConstructors() {
		return construct.length;
	}

	public Constructor getConstructor(int i) {
		return construct[i];
	}

	@Override
	public PatternExpression getPatternExpression() {
		throw new SleighException("Cannot use subtable in expression");
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		throw new SleighException("Cannot use subtable in expression");
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		throw new SleighException("Cannot use subtable in expression");
	}

	@Override
	public void printList(ParserWalker walker, ArrayList<Object> list) {
		throw new SleighException("Cannot use subtable in expression");
	}

	@Override
	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
//		int el = decoder.openElement(ELEM_SUBTABLE_SYM);
		int numct = (int) decoder.readSignedInteger(ATTRIB_NUMCT);
		construct = new Constructor[numct];		// Array must be built
		// before restoring constructors
		for (int i = 0; i < numct; ++i) {
			Constructor ct = new Constructor();
			ct.setId(i);
			construct[i] = ct;
			ct.decode(decoder, sleigh);
		}
		if (decoder.peekElement() != 0) {
			decisiontree = new DecisionNode();
			decisiontree.decode(decoder, null, this);
		}
		decoder.closeElement(ELEM_SUBTABLE_SYM.id());
	}

}
