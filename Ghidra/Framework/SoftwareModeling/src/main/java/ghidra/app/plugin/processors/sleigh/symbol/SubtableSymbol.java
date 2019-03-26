/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.app.plugin.processors.sleigh.*;
import ghidra.app.plugin.processors.sleigh.expression.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.mem.*;
import ghidra.util.xml.*;
import ghidra.xml.*;

import java.util.*;

/**
 * 
 *
 * A collection of Constructors or a Symbol representing
 * one out of a family of Constructors, choosen based on InstructionContext
 */
public class SubtableSymbol extends TripleSymbol {

	private Constructor[] construct;	// All the constructors in this table
	private DecisionNode decisiontree;	// The decision tree for this table

	public DecisionNode getDecisionNode() { return decisiontree; }
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#resolve(ghidra.app.plugin.processors.sleigh.ParserWalker, ghidra.app.plugin.processors.sleigh.SleighDebugLogger)
	 */
	@Override
    public Constructor resolve(ParserWalker walker, SleighDebugLogger debug) throws MemoryAccessException, UnknownInstructionException {
		return decisiontree.resolve(walker, debug);
	}
	
	public int getNumConstructors() { return construct.length; }
	public Constructor getConstructor(int i) { return construct[i]; }
	
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getPatternExpression()
	 */
	@Override
    public PatternExpression getPatternExpression() {
		throw new SleighException("Cannot use subtable in expression");
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#getFixedHandle(ghidra.app.plugin.processors.sleigh.FixedHandle, ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public void getFixedHandle(FixedHandle hand, ParserWalker walker) {
		throw new SleighException("Cannot use subtable in expression");
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#print(ghidra.app.plugin.processors.sleigh.ParserWalker)
	 */
	@Override
    public String print(ParserWalker walker) throws MemoryAccessException {
		throw new SleighException("Cannot use subtable in expression");
	}

	@Override
    public void printList(ParserWalker walker, ArrayList<Object> list) {
		throw new SleighException("Cannot use subtable in expression");
	}
	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.Symbol#restoreXml(org.jdom.Element, ghidra.app.plugin.processors.sleigh.SleighLanguage)
	 */
	@Override
    public void restoreXml(XmlPullParser parser, SleighLanguage sleigh) throws UnknownInstructionException {
	    XmlElement el = parser.start("subtable_sym");
		int numct = SpecXmlUtils.decodeInt(el.getAttribute("numct"));
		construct = new Constructor[numct];		// Array must be built
												// before restoring constructors
		for(int i=0;i<numct;++i) {
			Constructor ct = new Constructor();
			ct.setId(i);
			construct[i] = ct;
			ct.restoreXml(parser,sleigh);
		}
		if (!parser.peek().isEnd()) {
			decisiontree = new DecisionNode();
			decisiontree.restoreXml(parser,null,this);
		}
		parser.end(el);
	}

}
