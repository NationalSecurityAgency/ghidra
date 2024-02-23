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

import ghidra.app.util.bin.format.pdb2.pdbreader.MsSymbolIterator;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractPublicMsSymbol;
import ghidra.app.util.datatype.microsoft.GuidDataType;
import ghidra.app.util.datatype.microsoft.GuidUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;

/**
 * Applier for {@link AbstractPublicMsSymbol} symbols.
 */
public class PublicSymbolApplier extends MsSymbolApplier implements DirectSymbolApplier {

	private AbstractPublicMsSymbol symbol;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 * @param symbol the symbol for this applier
	 */
	public PublicSymbolApplier(DefaultPdbApplicator applicator, AbstractPublicMsSymbol symbol) {
		super(applicator);
		this.symbol = symbol;
	}

	@Override
	public void apply(MsSymbolIterator iter) throws PdbException, CancelledException {
		getValidatedSymbol(iter, true);
		Address symbolAddress = applicator.getAddress(symbol);

		String name = symbol.getName();
		if (applicator.isInvalidAddress(symbolAddress, name)) {
			return;
		}

		Address existingSymbolAddress =
			applicator.witnessSymbolNameAtAddress(name, symbolAddress);
		// TODO: Consider... could add restriction of not putting down symbol if it is mangled,
		//  as this would violate the uniqueness of the symbol... but we would also want to
		//  know that this situation was being presented.
		if (!symbolAddress.equals(existingSymbolAddress)) {
			// Note: there might be issues of thunk functions getting the same mangled name
			// as thunked functions, which violates the thesis of their being unique.
			// TODO: investigate this.
			applicator.createSymbol(symbolAddress, name, false);

			Program program = applicator.getProgram();
			if (GuidUtil.isGuidLabel(program, symbolAddress, name)) {
				try {
					DataUtilities.createData(program, symbolAddress, new GuidDataType(), -1,
						ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
				}
				catch (CodeUnitInsertionException e) {
					// ignore
				}
			}
		}
	}

	private AbstractPublicMsSymbol getValidatedSymbol(MsSymbolIterator iter, boolean iterate) {
		AbstractMsSymbol abstractSymbol = iterate ? iter.next() : iter.peek();
		if (!(abstractSymbol instanceof AbstractPublicMsSymbol pubSymbol)) {
			throw new AssertException(
				"Invalid symbol type: " + abstractSymbol.getClass().getSimpleName());
		}
		return pubSymbol;
	}

}
