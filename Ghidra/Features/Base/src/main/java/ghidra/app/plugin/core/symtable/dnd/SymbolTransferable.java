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
package ghidra.app.plugin.core.symtable.dnd;

import java.awt.Component;
import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import ghidra.program.model.symbol.Symbol;

public class SymbolTransferable implements Transferable {

	private static final DataFlavor[] FLAVORS = new DataFlavor[] { SymbolDataFlavor.DATA_FLAVOR };
	private List<Symbol> symbols;
	private Component source;

	public SymbolTransferable(Component source, List<Symbol> symbols) {
		this.source = Objects.requireNonNull(source);
		this.symbols = Objects.requireNonNull(symbols);
	}

	@Override
	public Object getTransferData(DataFlavor flavor)
			throws UnsupportedFlavorException, IOException {

		if (!SymbolDataFlavor.DATA_FLAVOR.equals(flavor)) {
			throw new UnsupportedFlavorException(flavor);
		}

		return new SymbolTransferData(source, symbols);
	}

	@Override
	public DataFlavor[] getTransferDataFlavors() {
		return FLAVORS;
	}

	@Override
	public boolean isDataFlavorSupported(DataFlavor flavor) {
		for (DataFlavor f : FLAVORS) {
			if (f.equals(flavor)) {
				return true;
			}
		}
		return false;
	}
}
