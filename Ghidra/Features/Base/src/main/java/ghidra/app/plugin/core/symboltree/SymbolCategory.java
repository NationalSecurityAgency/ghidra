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
package ghidra.app.plugin.core.symboltree;

import ghidra.program.model.symbol.SymbolType;

public class SymbolCategory {

	public static final SymbolCategory FUNCTION_CATEGORY = new SymbolCategory("Functions", SymbolType.FUNCTION);
	public static final SymbolCategory EXPORTS_CATEGORY = new SymbolCategory("Exports", SymbolType.LABEL);
	public static final SymbolCategory IMPORTS_CATEGORY = new SymbolCategory("Imports", SymbolType.LIBRARY);
	public static final SymbolCategory LABEL_CATEGORY = new SymbolCategory("Labels", SymbolType.LABEL);
	public static final SymbolCategory ROOT_CATEGORY = new SymbolCategory("Global", null);
	public static final SymbolCategory NAMESPACE_CATEGORY = new SymbolCategory("Namespaces", SymbolType.NAMESPACE);
	public static final SymbolCategory CLASS_CATEGORY = new SymbolCategory("Classes", SymbolType.CLASS);

	private String name;
	private SymbolType type;

	private SymbolCategory(String name, SymbolType type) {
		this.name = name;
		this.type = type;
	}

	public String getName() {
		return name;
	}

	public SymbolType getSymbolType() {
		return type;
	}
	/**
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return name;
    }
}
