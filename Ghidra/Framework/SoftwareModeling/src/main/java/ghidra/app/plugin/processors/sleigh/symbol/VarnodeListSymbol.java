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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import ghidra.app.plugin.processors.sleigh.Constructor;
import ghidra.app.plugin.processors.sleigh.FixedHandle;
import ghidra.app.plugin.processors.sleigh.ParserWalker;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.VarnodeData;
import ghidra.app.plugin.processors.sleigh.expression.PatternExpression;
import ghidra.app.plugin.processors.sleigh.expression.PatternValue;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

/**
 * 
 *
 * A ValueSymbol where the semantic context is obtained by looking
 * up the value in a table of VarnodeSymbols
 */
public class VarnodeListSymbol extends ValueSymbol {

	private VarnodeSymbol[] varnode_table;
	private boolean tableisfilled;

	public Collection<VarnodeSymbol> getVarnodeTable() {
		return Collections.unmodifiableList(Arrays.asList(varnode_table));
	}

	private void checkTableFill() {
		long min = getPatternValue().minValue();
		long max = getPatternValue().maxValue();
		tableisfilled = (min >= 0) && (max < varnode_table.length);
		for (int i = 0; i < varnode_table.length; ++i) {
			if (varnode_table[i] == null)
				tableisfilled = false;
		}
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.processors.sleigh.symbol.TripleSymbol#resolve(ghidra.app.plugin.processors.sleigh.ParserWalker, ghidra.app.plugin.processors.sleigh.SleighDebugLogger)
	 */
	@Override
	public Constructor resolve(ParserWalker walker, SleighDebugLogger debug)
			throws MemoryAccessException, UnknownInstructionException {
		if (!tableisfilled) {
			long ind = getPatternValue().getValue(walker);
			if ((ind < 0) || (ind >= varnode_table.length) || (varnode_table[(int) ind] == null)) {
				String errmsg = "Failed to resolve varnode <" + getName() + ">, index=" + ind;
				if (debug != null) {
					debug.append(errmsg + "\n");
				}
				throw new UnknownInstructionException(errmsg);
			}
		}
		return null;
	}

	@Override
	public void getFixedHandle(FixedHandle hand, ParserWalker walker) throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		VarnodeSymbol vnsym = varnode_table[ind];
		// Entry has already been tested for null by the resolve routine
		VarnodeData fix = vnsym.getFixedVarnode();
		hand.space = fix.space;
		hand.offset_space = null;	// Not a dynamic variable
		hand.offset_offset = fix.offset;
		hand.size = fix.size;
	}

	@Override
	public String print(ParserWalker walker) throws MemoryAccessException {
		int ind = (int) getPatternValue().getValue(walker);
		// Entry has already been tested for null by the resolve routine
		return varnode_table[ind].getName();
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage sleigh) {
		XmlElement el = parser.start("varlist_sym");
		patval = (PatternValue) PatternExpression.restoreExpression(parser, sleigh);
		ArrayList<VarnodeSymbol> varnodes = new ArrayList<>();
		SymbolTable symtab = sleigh.getSymbolTable();
		while (!parser.peek().isEnd()) {
			XmlElement subel = parser.start();
			if (subel.getName().equals("var")) {
				int id = SpecXmlUtils.decodeInt(subel.getAttribute("id"));
				varnodes.add((VarnodeSymbol) symtab.findSymbol(id));
			}
			else
				varnodes.add(null);
			parser.end(subel);
		}
		varnode_table = new VarnodeSymbol[varnodes.size()];

		for (int i = 0; i < varnode_table.length; ++i) {
			varnode_table[i] = varnodes.get(i);
		}
		checkTableFill();
		parser.end(el);
	}
}
