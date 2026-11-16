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
package ghidra.app.plugin.core.function;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.*;

/**
 * Class to wrap a symbol with methods that can be used provide column data to an
 * ObjectChooserDialog. This dialog is used to pick a function symbol when the
 * original query in {@link ThunkReferenceAddressDialog} finds multiple hits for a given name.
 */
public class ThunkSymbolDecorator {
	private Symbol symbol;

	public ThunkSymbolDecorator(Symbol s) {
		this.symbol = s;
	}

	public String getName() {
		return symbol.getName(true);
	}

	public String getNamespace() {
		Namespace namespace = symbol.getParentNamespace();
		if (namespace.isGlobal()) {
			return "";
		}
		return namespace.getName(true);
	}

	public String getLibrary() {
		Library library = symbol.getLibrary();
		return library == null ? "" : library.getName();
	}

	public String getAddress() {
		if (symbol.isExternal()) {
			return "<EXTERNAL>";
		}
		return symbol.getAddress().toString();
	}

	public String getSignature() {
		if (symbol.getSymbolType() == SymbolType.FUNCTION) {
			Function function = (Function) symbol.getObject();
			return function.getSignature().toString();
		}
		return symbol.getName();
	}

	public Symbol getSymbol() {
		return symbol;
	}

	@Override
	public String toString() {
		return symbol.getName();
	}
}
