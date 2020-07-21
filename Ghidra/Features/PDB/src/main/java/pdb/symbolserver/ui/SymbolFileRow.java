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
package pdb.symbolserver.ui;

import pdb.symbolserver.*;

/**
 * A row in the {@link SymbolFilePanel} find results table
 */
class SymbolFileRow {
	private SymbolFileLocation symbolFileLocation;
	private boolean isExactMatch;

	SymbolFileRow(SymbolFileLocation symbolFileLocation, boolean isExactMatch) {
		this.symbolFileLocation = symbolFileLocation;
		this.isExactMatch = isExactMatch;
	}

	SymbolFileInfo getSymbolFileInfo() {
		return symbolFileLocation.getFileInfo();
	}

	SymbolFileLocation getLocation() {
		return symbolFileLocation;
	}

	boolean isExactMatch() {
		return isExactMatch;
	}

	boolean isAvailableLocal() {
		return symbolFileLocation.getSymbolServer() instanceof SymbolStore;
	}

	void update(SymbolFileLocation newLocation, boolean newIsExactMatch) {
		this.symbolFileLocation = newLocation;
		this.isExactMatch = newIsExactMatch;
	}

}
