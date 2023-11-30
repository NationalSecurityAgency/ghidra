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
package sarif.export.symbols;

import ghidra.program.database.symbol.ClassSymbol;
import ghidra.program.database.symbol.LibrarySymbol;
import ghidra.program.database.symbol.NamespaceSymbol;
import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

public class ExtSymbol implements IsfObject {

	String name;
	String location;
	Boolean namespaceIsClass;
	String kind;
	String type;
	String sourceType;
	boolean primary;

	public ExtSymbol(Symbol symbol) {
		name = symbol.getName();
		location = getNamespace(symbol);
		kind = checkGlobal(symbol) ? "global" : "local";
		sourceType = symbol.getSource().toString();
		primary = symbol.isPrimary();
		if (symbol instanceof ClassSymbol) {
			type = "class";
		} else if (symbol instanceof LibrarySymbol) {
			type = "library";
		} else if (symbol instanceof NamespaceSymbol) {
			type = "namespace";
		}
		// NB: DO NOT add type==function, as this will affect the execution order
		//if (symbol instanceof FunctionSymbol fs) {
		//	type = "function";
		//}
	}

	/**
	 * Returns the name of symbol qualified with any namespace information. For
	 * example, "User32.dll::SomeClass::printf".
	 */
	private String getNamespace(Symbol symbol) {
		StringBuffer buffer = new StringBuffer();
		Namespace namespace = symbol.getParentNamespace();
		while (!namespace.isGlobal()) {
			buffer.insert(0, namespace.getName() + "::");
			if (namespace instanceof GhidraClass) {
				namespaceIsClass = true;
			}
			namespace = namespace.getParentNamespace();
		}
		return buffer.toString();
	}

	private boolean checkGlobal(Symbol symbol) {
		if (symbol.isGlobal()) {
			return true;
		}
		Namespace parent = symbol.getParentNamespace();
		if (parent instanceof Library) {
			return true;
		}
		return false;
	}

}
