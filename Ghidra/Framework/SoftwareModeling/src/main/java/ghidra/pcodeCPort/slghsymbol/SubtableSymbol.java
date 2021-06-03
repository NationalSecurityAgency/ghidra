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

import java.io.PrintStream;
import java.util.*;

import org.jdom.Element;

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.*;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.slghpatexpress.PatternExpression;
import ghidra.pcodeCPort.slghpatexpress.TokenPattern;
import ghidra.pcodeCPort.slghpattern.DisjointPattern;
import ghidra.pcodeCPort.slghpattern.Pattern;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

public class SubtableSymbol extends TripleSymbol {

	private TokenPattern pattern;
	private boolean beingbuilt, errors;
	// All the Constructors in this table
	private VectorSTL<Constructor> construct = new VectorSTL<Constructor>();
	private DecisionNode decisiontree;

	public SubtableSymbol(Location location) {
		super(location);
		pattern = null;
		decisiontree = null;
	} // For use with restoreXml

	public boolean isBeingBuilt() {
		return beingbuilt;
	}

	public boolean isError() {
		return errors;
	}

	public void addConstructor(Constructor ct) {
		ct.setId(construct.size());
		construct.push_back(ct);
	}

	@Override
	public Constructor resolve(ParserWalker pos) {
		return decisiontree.resolve(pos);
	}

	public TokenPattern getPattern() {
		return pattern;
	}

	public int getNumConstructors() {
		return construct.size();
	}

	public Constructor getConstructor(int id) {
		return construct.get(id);
	}

	@Override
	public PatternExpression getPatternExpression() {
		throw new SleighError("Cannot use subtable in expression", null);
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker pos) {
		throw new SleighError("Cannot use subtable in expression", null);
	}

	@Override
	public int getSize() {
		return -1;
	}

	@Override
	public void print(PrintStream s, ParserWalker pos) {
		throw new SleighError("Cannot use subtable in expression", null);
	}

	@Override
	public void collectLocalValues(ArrayList<Long> results) {
		for (Constructor curConstruct : construct) {
			curConstruct.collectLocalExports(results);
		}
	}

	@Override
	public symbol_type getType() {
		return symbol_type.subtable_symbol;
	}

	public SubtableSymbol(Location location, String nm) {
		super(location, nm);
		beingbuilt = false;
		pattern = null;
		decisiontree = null;
	}

	@Override
	public void dispose() {
		if (pattern != null) {
			pattern.dispose();
		}
		if (decisiontree != null) {
			decisiontree.dispose();
		}
		IteratorSTL<Constructor> iter;
		for (iter = construct.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().dispose();
		}
	}

	@Override
	public void saveXml(PrintStream s) {
		if (decisiontree == null) {
			return; // Not fully formed
		}
		s.append("<subtable_sym");
		saveSleighSymbolXmlHeader(s);
		s.append(" numct=\"").print(construct.size());
		s.append("\">\n");
		for (int i = 0; i < construct.size(); ++i) {
			construct.get(i).saveXml(s);
		}
		decisiontree.saveXml(s);
		s.append("</subtable_sym>\n");
	}

	@Override
	public void saveXmlHeader(PrintStream s) {
		s.append("<subtable_sym_head");
		saveSleighSymbolXmlHeader(s);
		s.append("/>\n");
	}

	@Override
	public void restoreXml(Element el, SleighBase trans) {
		int numct = XmlUtils.decodeUnknownInt(el.getAttributeValue("numct"));
		construct.reserve(numct);

		List<?> children = el.getChildren();
		Iterator<?> iter = children.iterator();
		while (iter.hasNext()) {
			Element child = (Element) iter.next();
			if (child.getName().equals("constructor")) {
				Constructor ct = new Constructor(null);
				addConstructor(ct);
				ct.restoreXml(child, trans);
			}
			else if (child.getName().equals("decision")) {
				decisiontree = new DecisionNode();
				decisiontree.restoreXml(child, null, this);
			}
		}
		pattern = null;
		beingbuilt = false;
		errors = false;
	}

	// Associate pattern disjoints to constructors
	public void buildDecisionTree(DecisionProperties props) {
		if (pattern == null) {
			return; // Pattern not fully formed
		}
		decisiontree = new DecisionNode(null);
		for (int i = 0; i < construct.size(); ++i) {
			Constructor constructor = construct.get(i);
			TokenPattern tpat = constructor.getPattern();
			Pattern pat = tpat.getPattern();
			if (pat.numDisjoint() == 0) {
				decisiontree.addConstructorPair((DisjointPattern) pat, construct.get(i));
			}
			else {
				for (int j = 0; j < pat.numDisjoint(); ++j) {
					decisiontree.addConstructorPair(pat.getDisjoint(j), construct.get(i));
				}
			}
		}
		decisiontree.split(props); // Create the decision strategy
	}

	public TokenPattern buildPattern(PrintStream s) {
		if (pattern != null) {
			return pattern; // Already built
		}

		errors = false;
		beingbuilt = true;
		pattern = new TokenPattern(Location.INTERNALLY_DEFINED);

		if (construct.empty()) {
			s.append("Error: There are no constructors in table: " + getName()).append("\n");
			errors = true;
			return pattern;
		}
		try {
			construct.front().buildPattern(s);
		}
		catch (SleighError err) {
			s.append("Error: ").append(err.getMessage()).append(": for ");
			construct.front().printInfo(s);
			s.println();
			errors = true;
		}
		pattern = construct.front().getPattern();
		for (int i = 1; i < construct.size(); ++i) {
			try {
				Constructor constructor = construct.get(i);
				constructor.buildPattern(s);
			}
			catch (SleighError err) {
				s.append("Error: ").append(err.getMessage()).append(": for ");
				construct.get(i).printInfo(s);
				s.println();
				errors = true;
			}
//            pattern.copyInto(construct.get(i).getPattern().commonSubPattern(pattern));
			pattern = construct.get(i).getPattern().commonSubPattern(pattern);
			pattern.simplifyPattern();
		}
		beingbuilt = false;
		return pattern;
	}

}
