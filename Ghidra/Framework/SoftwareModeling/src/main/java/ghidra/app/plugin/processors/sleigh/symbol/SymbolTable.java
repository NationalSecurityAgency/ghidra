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

import static ghidra.pcode.utils.SlaFormat.*;

import java.util.ArrayList;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.pcode.Decoder;
import ghidra.program.model.pcode.DecoderException;

/**
 * Full symbol table for sleigh
 */
public class SymbolTable {
	private Symbol[] symbollist;		// List of all Symbols, index by id
	private UseropSymbol[] userOps;		// List all user ops, indexed by index
	private SymbolScope[] table;		// All SymbolScopes, indexed by id
	private SymbolScope curscope;		// Current scope

	private SymbolScope skipScope(int i) {
		SymbolScope res = curscope;
		while (i > 0) {
			if (res.getParent() == null) {
				return res;
			}
			res = res.getParent();
			--i;
		}
		return res;
	}

	private Symbol findSymbolInternal(SymbolScope scope, String nm) {
		while (scope != null) {
			Symbol res = scope.findSymbol(nm);
			if (res != null) {
				return res;
			}
			scope = scope.getParent();
		}
		return null;
	}

	public SymbolTable() {
		curscope = null;
	}

	public SymbolScope getCurrentScope() {
		return curscope;
	}

	public SymbolScope getGlobalScope() {
		return table[0];
	}

	public void setCurrentScope(SymbolScope scope) {
		curscope = scope;
	}

	public Symbol findSymbol(String nm) {
		return findSymbolInternal(curscope, nm);
	}

	public Symbol findSymbol(String nm, int skip) {
		return findSymbolInternal(skipScope(skip), nm);
	}

	public Symbol findGlobalSymbol(String nm) {
		return findSymbolInternal(table[0], nm);
	}

	public Symbol[] getSymbolList() {
		return symbollist;
	}

	public Symbol findSymbol(int id) {
		return symbollist[id];
	}

	public void decode(Decoder decoder, SleighLanguage sleigh) throws DecoderException {
		int el = decoder.openElement(ELEM_SYMBOL_TABLE);
		int scopesize = (int) decoder.readSignedInteger(ATTRIB_SCOPESIZE);
		table = new SymbolScope[scopesize];
		int symsize = (int) decoder.readSignedInteger(ATTRIB_SYMBOLSIZE);
		symbollist = new Symbol[symsize];

		// Decode the scopes
		for (int i = 0; i < scopesize; ++i) {
			int subel = decoder.openElement(ELEM_SCOPE);
			int id = (int) decoder.readUnsignedInteger(ATTRIB_ID);
			int parent = (int) decoder.readUnsignedInteger(ATTRIB_PARENT);
			SymbolScope sscope;
			if (parent == id) {
				sscope = null;
			}
			else {
				sscope = table[parent];
			}
			table[id] = new SymbolScope(sscope, id);
			decoder.closeElement(subel);
		}
		curscope = table[0];		// Initial scope is global scope

		for (int i = 0; i < symsize; ++i) {	// Decode the symbol shells
			decodeSymbolHeader(decoder);
		}

		ArrayList<UseropSymbol> userops = new ArrayList<UseropSymbol>();
		while (decoder.peekElement() != 0) {				// Decode the symbol content
			decoder.openElement();
			int id = (int) decoder.readUnsignedInteger(ATTRIB_ID);
			Symbol sym = findSymbol(id);
			sym.decode(decoder, sleigh);
			// Tag closed by decode method
//			decoder.closeElement(subel);
			if (sym instanceof UseropSymbol) {
				userops.add((UseropSymbol) sym);
			}
		}
		userOps = new UseropSymbol[userops.size()];
		userops.toArray(userOps);
		decoder.closeElement(el);
	}

	public void decodeSymbolHeader(Decoder decoder) throws DecoderException {
		Symbol sym;
		int el = decoder.peekElement();
		if (el == ELEM_USEROP_HEAD.id()) {
			sym = new UseropSymbol();
		}
		else if (el == ELEM_EPSILON_SYM_HEAD.id()) {
			sym = new EpsilonSymbol();
		}
		else if (el == ELEM_VALUE_SYM_HEAD.id()) {
			sym = new ValueSymbol();
		}
		else if (el == ELEM_VALUEMAP_SYM_HEAD.id()) {
			sym = new ValueMapSymbol();
		}
		else if (el == ELEM_NAME_SYM_HEAD.id()) {
			sym = new NameSymbol();
		}
		else if (el == ELEM_VARNODE_SYM_HEAD.id()) {
			sym = new VarnodeSymbol();
		}
		else if (el == ELEM_CONTEXT_SYM_HEAD.id()) {
			sym = new ContextSymbol();
		}
		else if (el == ELEM_VARLIST_SYM_HEAD.id()) {
			sym = new VarnodeListSymbol();
		}
		else if (el == ELEM_OPERAND_SYM_HEAD.id()) {
			sym = new OperandSymbol();
		}
		else if (el == ELEM_START_SYM_HEAD.id()) {
			sym = new StartSymbol();
		}
		else if (el == ELEM_END_SYM_HEAD.id()) {
			sym = new EndSymbol();
		}
		else if (el == ELEM_NEXT2_SYM_HEAD.id()) {
			sym = new Next2Symbol();
		}
		else if (el == ELEM_SUBTABLE_SYM_HEAD.id()) {
			sym = new SubtableSymbol();
		}
		else {
			throw new SleighException("Bad symbol encoding");
		}
		sym.decodeHeader(decoder);	// Decode basic elements of symbol
		symbollist[sym.getId()] = sym;
		table[sym.getScopeId()].addSymbol(sym);
	}

	public int getNumberOfUserDefinedOpNames() {
		return userOps.length;
	}

	public String getUserDefinedOpName(int index) {
		if (index < userOps.length) {
			return userOps[index].getName();
		}
		return null;
	}
}
