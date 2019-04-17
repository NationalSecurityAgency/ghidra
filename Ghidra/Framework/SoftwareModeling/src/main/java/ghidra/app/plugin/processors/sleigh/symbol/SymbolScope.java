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
 * Created on Feb 7, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh.symbol;

import ghidra.app.plugin.processors.sleigh.SleighException;

import java.util.HashMap;

/**
 * 
 *
 * A single scope of symbol names for sleigh
 */
public class SymbolScope {
	private SymbolScope parent;		// next-most global scope
	private HashMap<String, Symbol> tree;			// Map of String(name) -> Symbol
	private int id;					// Unique id of the scope
	
	public SymbolScope(SymbolScope p,int i) {
		parent = p;
		id = i;
		tree = new HashMap<String, Symbol>();
	}
	
	public SymbolScope getParent() { return parent; }
	
	public void addSymbol(Symbol a) {
		Symbol res = tree.put(a.getName(),a);
		if (res != null)
			throw new SleighException("Duplicate symbol");
	}
	
	public Symbol findSymbol(String nm) {
		return tree.get(nm);
	}
	
	public int getId() { return id; }
}
