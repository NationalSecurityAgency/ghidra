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
package ghidra.app.util.pdb.pdbapplicator;

import java.util.List;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractPublicMsSymbol} symbols.
 */
public class PublicSymbolApplier extends AbstractMsSymbolApplier {

	private AbstractPublicMsSymbol symbol;
	private Address symbolAddress = null;
	private Address existingSymbolAddress = null;

	public PublicSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		super(applicator, iter);
		AbstractMsSymbol abstractSymbol = iter.next();
		if (!(abstractSymbol instanceof AbstractPublicMsSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		symbol = (AbstractPublicMsSymbol) abstractSymbol;
	}

	@Override
	public void applyTo(AbstractMsSymbolApplier applyToApplier) {
		// Do nothing.
	}

	@Override
	public void apply() throws CancelledException, PdbException {

		symbolAddress = applicator.reladdr(symbol);
		if (!Address.NO_ADDRESS.equals(symbolAddress)) {

			if (getName().startsWith("?")) { // mangled... should be unique
				List<Symbol> existingSymbols =
					applicator.getProgram().getSymbolTable().getGlobalSymbols(getName());
				if (existingSymbols.size() == 1) {
					existingSymbolAddress = existingSymbols.get(0).getAddress();
					applicator.putRemapAddressByAddress(symbolAddress, existingSymbolAddress);
				}
				else if (existingSymbols.size() == 0) {
					String name = symbol.getName();
					if (!applicator.createSymbol(symbolAddress, name, true)) {
						applicator.appendLogMsg(
							"Unable to create symbol " + name + " at " + symbolAddress);
					}
				}
				else {
					applicator.appendLogMsg(
						"Unexpected multiple mangled symbols of same name: " + getName());
				}
			}
		}
		else {
			String message = "Could not apply symbol at NO_ADDRESS: " + symbol.getName();
			Msg.info(this, message);
			PdbLog.message(message);
		}
	}

	Address getAddress() {
		return symbolAddress;
	}

	Address getAddressRemappedThroughPublicSymbol() {
		return (existingSymbolAddress != null) ? existingSymbolAddress : symbolAddress;
	}

	String getName() {
		return symbol.getName();
	}
}
