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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

import java.util.ArrayList;

/**
 * 
 *
 * Full symbol table for sleigh
 */
public class SymbolTable {
	private Symbol[] symbollist;		// List of all Symbols, index by id
	private UseropSymbol[] userOps;		// List all user ops, indexed by index
	private SymbolScope[] table;		// All SymbolScopes, indexed by id
	private SymbolScope curscope;		// Current scope
	
	private SymbolScope skipScope(int i) {
		SymbolScope res = curscope;
		while(i>0) {
			if (res.getParent() == null)
				return res;
			res = res.getParent();
			--i;
		}
		return res;
	}
	
	private Symbol findSymbolInternal(SymbolScope scope,String nm) {
		while(scope != null) {
			Symbol res = scope.findSymbol(nm);
			if (res != null)
				return res;
			scope = scope.getParent();
		}
		return null;
	}
	
	public SymbolTable() { curscope = null; }
	
	public SymbolScope getCurrentScope() { return curscope; }
	
	public SymbolScope getGlobalScope() { return table[0]; }
	
	public void setCurrentScope(SymbolScope scope) { curscope = scope; }
	
	public Symbol findSymbol(String nm) {
		return findSymbolInternal(curscope,nm);
	}

	public Symbol findSymbol(String nm,int skip) {
		return findSymbolInternal(skipScope(skip),nm);
	}
	
	public Symbol findGlobalSymbol(String nm) {
		return findSymbolInternal(table[0],nm);
	}

	public Symbol[] getSymbolList() { return symbollist; }
	
	public Symbol findSymbol(int id) {
		return symbollist[id];
	}
	
	public void restoreXml(XmlPullParser parser, SleighLanguage sleigh) throws UnknownInstructionException {
	    XmlElement el = parser.start("symbol_table");
		int scopesize = SpecXmlUtils.decodeInt(el.getAttribute("scopesize"));
		table = new SymbolScope[scopesize];
		int symsize = SpecXmlUtils.decodeInt(el.getAttribute("symbolsize"));
		symbollist = new Symbol[symsize];
		
							// Restore the scopes
		for(int i=0;i<scopesize;++i) {
		    XmlElement subel = parser.start("scope");
			int id = SpecXmlUtils.decodeInt(subel.getAttribute("id"));
			int parent = SpecXmlUtils.decodeInt(subel.getAttribute("parent"));
			SymbolScope sscope;
			if (parent==id)
				sscope = null;
			else
				sscope = table[parent];
			table[id] = new SymbolScope(sscope,id);
			parser.end(subel);
		}
		curscope = table[0];		// Initial scope is global scope
		
		for(int i=0;i<symsize;++i) {	// Restore the symbol shells
			restoreSymbolHeader(parser);
		}

		ArrayList<UseropSymbol> userops = new ArrayList<UseropSymbol>();
		XmlElement subel = parser.peek();
		while(!subel.getName().equals("symbol_table")) {			// Restore the symbol content
			int id = SpecXmlUtils.decodeInt(subel.getAttribute("id"));
			Symbol sym = findSymbol(id);
			sym.restoreXml(parser,sleigh);
			if (sym instanceof UseropSymbol)
				userops.add((UseropSymbol)sym);
			subel = parser.peek();
		}
		userOps = new UseropSymbol[userops.size()];
		userops.toArray(userOps);
		parser.end(el);
	}
	
	public void restoreSymbolHeader(XmlPullParser parser) {
		Symbol sym;
		XmlElement el = parser.peek();
		if (el.getName().equals("userop_head"))
			sym = new UseropSymbol();
		else if (el.getName().equals("epsilon_sym_head"))
			sym = new EpsilonSymbol();
		else if (el.getName().equals("value_sym_head"))
			sym = new ValueSymbol();
		else if (el.getName().equals("valuemap_sym_head"))
			sym = new ValueMapSymbol();
		else if (el.getName().equals("name_sym_head"))
			sym = new NameSymbol();
		else if (el.getName().equals("varnode_sym_head"))
			sym = new VarnodeSymbol();
		else if (el.getName().equals("context_sym_head"))
			sym = new ContextSymbol();
		else if (el.getName().equals("varlist_sym_head"))
			sym = new VarnodeListSymbol();
		else if (el.getName().equals("operand_sym_head"))
			sym = new OperandSymbol();
		else if (el.getName().equals("start_sym_head"))
			sym = new StartSymbol();
		else if (el.getName().equals("end_sym_head"))
			sym = new EndSymbol();
		else if (el.getName().equals("subtable_sym_head"))
			sym = new SubtableSymbol();
		else
			throw new SleighException("Bad symbol xml");
		sym.restoreHeaderXml(parser);	// Restore basic elements of symbol
		symbollist[sym.getId()] = sym;
		table[sym.getScopeId()].addSymbol(sym);
	}

	public int getNumberOfUserDefinedOpNames() {
		return userOps.length;
	}
	
	public String getUserDefinedOpName(int index) {
		if (index < userOps.length)
			return userOps[index].getName();
		return null;
	}
}
