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

import generic.stl.IteratorSTL;
import generic.stl.VectorSTL;
import ghidra.pcodeCPort.context.SleighError;
import ghidra.pcodeCPort.sleighbase.SleighBase;
import ghidra.pcodeCPort.utils.XmlUtils;
import ghidra.sleigh.grammar.Location;

import java.io.PrintStream;
import java.util.Iterator;
import java.util.List;

import org.jdom.Element;

public class SymbolTable {

	private VectorSTL<SleighSymbol> symbollist = new VectorSTL<SleighSymbol>();
	private VectorSTL<SymbolScope> table = new VectorSTL<SymbolScope>();
	private SymbolScope curscope;

	public SymbolTable() {
		curscope = null;
	}

	public SymbolScope getCurrentScope() {
		return curscope;
	}

	public SymbolScope getGlobalScope() {
		return table.get(0);
	}

	public void setCurrentScope(SymbolScope scope) {
		curscope = scope;
	}

	public VectorSTL<SleighSymbol> getUnsoughtSymbols() {
		VectorSTL<SleighSymbol> result = new VectorSTL<SleighSymbol>();
		IteratorSTL<SleighSymbol> siter;
		for (siter = symbollist.begin(); !siter.isEnd(); siter.increment()) {
			SleighSymbol sleighSymbol = siter.get();
			if (!sleighSymbol.wasSought()) {
				result.push_back(sleighSymbol);
			}
		}
		return result;
	}

	public SleighSymbol findSymbol(String nm) {
		return findSymbolInternal(curscope, nm);
	}

	public SleighSymbol findSymbol(String nm, int skip) {
		return findSymbolInternal(skipScope(skip), nm);
	}

	public SleighSymbol findGlobalSymbol(String nm) {
		return findSymbolInternal(table.get(0), nm);
	}

	public SleighSymbol findSymbol(int id) {
		SleighSymbol sleighSymbol = symbollist.get(id);
		sleighSymbol.setWasSought(true);
		return sleighSymbol;
	}

	public void dispose() {
		IteratorSTL<SymbolScope> iter;
		for (iter = table.begin(); !iter.isEnd(); iter.increment()) {
			iter.get().dispose();
		}
		IteratorSTL<SleighSymbol> siter;
		for (siter = symbollist.begin(); !siter.isEnd(); siter.increment()) {
			siter.get().dispose();
		}
	}

	public void addScope() {
		curscope = new SymbolScope(curscope, table.size());
		table.push_back(curscope);
	}

	public void popScope() {
		if (curscope != null) {
			curscope = curscope.getParent();
		}
	}

	private SymbolScope skipScope(int i) {
		SymbolScope res = curscope;
		while (i > 0) {
			if (res.parent == null) {
				return res;
			}
			res = res.parent;
			--i;
		}
		return res;
	}

	public void addGlobalSymbol(SleighSymbol a) {
		a.id = symbollist.size();
		symbollist.push_back(a);
		SymbolScope scope = getGlobalScope();
		a.scopeid = scope.getId();
		SleighSymbol res = scope.addSymbol(a);
		if (res != a) {
			throw new SleighError("Duplicate symbol name: " + a.getName() +
				" (previously defined at " + res.location + ")", a.getLocation());
		}
	}

	public int addSymbol(SleighSymbol a) {
		a.id = symbollist.size();
		symbollist.push_back(a);
		a.scopeid = curscope.getId();
		SleighSymbol res = curscope.addSymbol(a);
		if (res != a) {
			throw new SleighError("Duplicate symbol name: " + a.getName() +
				" (previously defined at " + res.location + ")", a.getLocation());
		}
		return a.id;
	}

	private static final String NEWLINE = System.getProperty("line.separator");

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		SymbolScope scope = curscope;
		while (scope != null) {
			sb.append(scope);
			sb.append(NEWLINE);
			scope = scope.getParent();
		}
		return sb.toString();
	}

	private SleighSymbol findSymbolInternal(SymbolScope scope, String nm) {
		SleighSymbol res;

		while (scope != null) {
			res = scope.findSymbol(nm);
			if (res != null) {
				res.setWasSought(true);
				return res;
			}
			scope = scope.getParent(); // Try higher scope
		}
		return null;
	}

	// Replace symbol a with symbol b
	// assuming a and b have the same name
	public void replaceSymbol(SleighSymbol a, SleighSymbol b) {
		SleighSymbol sym;
		int i = table.size() - 1;

		while (i >= 0) { // Find the particular symbol
			sym = table.get(i).findSymbol(a.getName());
			if (sym == a) {
				table.get(i).removeSymbol(a);
				b.id = a.id;
				b.scopeid = a.scopeid;
				symbollist.set(b.id, b);
				table.get(i).addSymbol(b);
				a.dispose();
				return;
			}
			--i;
		}
	}

	public void saveXml(PrintStream s) {
		s.append("<symbol_table");
		s.append(" scopesize=\"");
		s.print(table.size());
		s.append("\"");
		s.append(" symbolsize=\"");
		s.print(symbollist.size());
		s.append("\">\n");
		for (int i = 0; i < table.size(); ++i) {
			s.append("<scope id=\"0x");
			s.append(Long.toHexString(table.get(i).getId()));
			s.append("\"");
			s.append(" parent=\"0x");
			if (table.get(i).getParent() == null) {
				s.append("0");
			}
			else {
				s.append(Long.toHexString(table.get(i).getParent().getId()));
			}
			s.append("\"/>\n");
		}

		// First save the headers
		for (int i = 0; i < symbollist.size(); ++i) {
			symbollist.get(i).saveXmlHeader(s);
		}

		// Now save the content of each symbol
		for (int i = 0; i < symbollist.size(); ++i) { // Must save IN ORDER
			symbollist.get(i).saveXml(s);
		}
		s.append("</symbol_table>\n");
	}

	public void restoreXml(Element el, SleighBase trans) {
		int size = XmlUtils.decodeUnknownInt(el.getAttributeValue("scopesize"));
		for (int i = 0; i < size; i++) {
			table.push_back(null);
		}
		size = XmlUtils.decodeUnknownInt(el.getAttributeValue("symbolsize"));
		for (int i = 0; i < size; i++) {
			symbollist.push_back(null);
		}

		List<?> list = el.getChildren();
		Iterator<?> iter = list.iterator();
		for (int i = 0; i < table.size(); ++i) { // Restore the scopes
			Element subel = (Element) iter.next();
			if (!subel.getName().equals("scope")) {
				throw new SleighError("Misnumbered symbol scopes", null);
			}
			int id = XmlUtils.decodeUnknownInt(subel.getAttributeValue("id"));
			int parent = XmlUtils.decodeUnknownInt(subel.getAttributeValue("parent"));
			SymbolScope parscope = (parent == id) ? null : table.get(parent);
			table.set(id, new SymbolScope(parscope, id));
		}
		curscope = table.get(0); // Current scope is global

		// Now restore the symbol shells
		for (int i = 0; i < symbollist.size(); ++i) {
			Element child = (Element) iter.next();
			restoreSymbolHeader(child);
		}
		// Now restore the symbol content
		while (iter.hasNext()) {
			Element subel = (Element) iter.next();
			int id = XmlUtils.decodeUnknownInt(subel.getAttributeValue("id"));
			SleighSymbol sym = findSymbol(id);
			sym.restoreXml(subel, trans);
		}
	}

	// Put the shell of a symbol in the symbol table
	// in order to allow recursion
	public void restoreSymbolHeader(Element el) {
		SleighSymbol sym;
		// this is where you can restore the actual location from in the
		// future if you so wish (of course, all the saveXml...need
		// to be updated properly too)
		Location location = null;
		if (el.getName().equals("userop_head")) {
			sym = new UserOpSymbol(location);
		}
		else if (el.getName().equals("epsilon_sym_head")) {
			sym = new EpsilonSymbol(location);
		}
		else if (el.getName().equals("value_sym_head")) {
			sym = new ValueSymbol(location);
		}
		else if (el.getName().equals("valuemap_sym_head")) {
			sym = new ValueMapSymbol(location);
		}
		else if (el.getName().equals("name_sym_head")) {
			sym = new NameSymbol(location);
		}
		else if (el.getName().equals("varnode_sym_head")) {
			sym = new VarnodeSymbol(location);
		}
		else if (el.getName().equals("context_sym_head")) {
			sym = new ContextSymbol(location);
		}
		else if (el.getName().equals("varlist_sym_head")) {
			sym = new VarnodeListSymbol(location);
		}
		else if (el.getName().equals("operand_sym_head")) {
			sym = new OperandSymbol(location);
		}
		else if (el.getName().equals("start_sym_head")) {
			sym = new StartSymbol(location);
		}
		else if (el.getName().equals("end_sym_head")) {
			sym = new EndSymbol(location);
		}
		else if (el.getName().equals("subtable_sym_head")) {
			sym = new SubtableSymbol(location);
		}
		else {
			throw new SleighError("Bad symbol xml", null);
		}
		sym.restoreXmlHeader(el); // Restore basic elements of symbol
		symbollist.set(sym.id, sym); // Put the basic symbol in the table
		table.get(sym.scopeid).addSymbol(sym); // to allow recursion
	}

	// Get rid of unsavable symbols and scopes
	public void purge() {
		SleighSymbol sym;
		for (int symbolIndex = 0; symbolIndex < symbollist.size(); ++symbolIndex) {
			sym = symbollist.get(symbolIndex);
			if (sym == null) {
				continue;
			}
			if (sym.scopeid != 0) { // Not in global scope
				if (sym.getType() == symbol_type.operand_symbol) {
					continue;
				}
			}
			else {
				switch (sym.getType()) {
					case space_symbol:
					case token_symbol:
					case epsilon_symbol:
					case section_symbol:
						break;
					case macro_symbol: { // Delete macro's local symbols
						MacroSymbol macro = (MacroSymbol) sym;
						for (int macroIndex = 0; macroIndex < macro.getNumOperands(); ++macroIndex) {
							SleighSymbol opersym = macro.getOperand(macroIndex);
							table.get(opersym.scopeid).removeSymbol(opersym);
							symbollist.set(opersym.id, null);
							opersym.dispose();
						}
						break;
					}
					case subtable_symbol: { // Delete unused subtables
						SubtableSymbol subsym = (SubtableSymbol) sym;
						if (subsym.getPattern() != null) {
							continue;
						}
						for (int subtableIndex = 0; subtableIndex < subsym.getNumConstructors(); ++subtableIndex) { // Go thru
							// each
							// constructor
							Constructor con = subsym.getConstructor(subtableIndex);
							for (int operandIndex = 0; operandIndex < con.getNumOperands(); ++operandIndex) { // Go thru each operand
								OperandSymbol oper = con.getOperand(operandIndex);
								table.get(oper.scopeid).removeSymbol(oper);
								symbollist.set(oper.id, null);
								oper.dispose();
							}
						}
						break; // Remove the subtable symbol itself
					}
					default:
						continue;
				}
			}
			table.get(sym.scopeid).removeSymbol(sym); // Remove the symbol
			symbollist.set(symbolIndex, null);
			sym.dispose();
		}
		for (int tableIndex = 1; tableIndex < table.size(); ++tableIndex) { // Remove any empty scopes
			if (table.get(tableIndex).tree.isEmpty()) {
				table.get(tableIndex).dispose();
				table.set(tableIndex, null);
			}
		}
		renumber();
	}

	// Renumber all the scopes and symbols
	// so that there are no gaps
	private void renumber() {
		VectorSTL<SymbolScope> newtable = new VectorSTL<SymbolScope>();
		VectorSTL<SleighSymbol> newsymbol = new VectorSTL<SleighSymbol>();

		// First renumber the scopes
		SymbolScope scope = null;
		for (int i = 0; i < table.size(); ++i) {
			scope = table.get(i);
			if (scope != null) {
				scope.id = newtable.size();
				newtable.push_back(scope);
			}
		}
		// Now renumber the symbols
		SleighSymbol sym = null;
		for (int i = 0; i < symbollist.size(); ++i) {
			sym = symbollist.get(i);
			if (sym != null) {
				sym.scopeid = table.get(sym.scopeid).id;
				sym.id = newsymbol.size();
				newsymbol.push_back(sym);
			}
		}
		table = newtable;
		symbollist = newsymbol;
	}
}
