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

import java.util.Objects;

import ghidra.app.util.bin.format.pdb2.pdbreader.PdbException;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;
import ghidra.app.util.pdb.pdbapplicator.SymbolGroup.AbstractMsSymbolIterator;
import ghidra.util.exception.CancelledException;

public abstract class AbstractMsSymbolApplier {
	protected PdbApplicator applicator;
	protected AbstractMsSymbolIterator iter;
	protected long currentOffset;

	public AbstractMsSymbolApplier(PdbApplicator applicator, AbstractMsSymbolIterator iter) {
		Objects.requireNonNull(applicator, "applicator cannot be null");
		Objects.requireNonNull(iter, "symbolGroup cannot be null");
		this.applicator = applicator;
		this.iter = iter;
		currentOffset = iter.getCurrentOffset();
	}

	/**
	 * Sets the offset of the {@link SymbolGroup} back to the state when this applicator was
	 * created.
	 */
	protected void resetOffset() {
		iter.initGetByOffset(currentOffset);
	}

	/**
	 * Apply the next and any desired subsequent {@link AbstractMsSymbol AbstractMsSymbols} from
	 * the {@link SymbolGroup} to a program.
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException upon user cancellation
	 */
	public abstract void apply() throws PdbException, CancelledException;

	/**
	 * Applies logic of this class to another {@link AbstractMsSymbolApplier} instead of to
	 *  "the program."
	 * @param applyToApplier the applier to which the logic of this class is applied.
	 * @throws PdbException if there was a problem processing the data.
	 * @throws CancelledException upon user cancellation.
	 */
	public abstract void applyTo(AbstractMsSymbolApplier applyToApplier)
			throws PdbException, CancelledException;

	/**
	 * Manages block nesting for symbols/appliers that represent the beginning or end of blocks.
	 *  The default is to do nothing.  Otherwise the appliers should implement the appropriate
	 *  logic.  
	 * @param applierParam the applier which is managing blocks, which is typically
	 *  {@link FunctionSymbolApplier}.
	 */
	public void manageBlockNesting(AbstractMsSymbolApplier applierParam) {
		// Do nothing by default.
	}

}
