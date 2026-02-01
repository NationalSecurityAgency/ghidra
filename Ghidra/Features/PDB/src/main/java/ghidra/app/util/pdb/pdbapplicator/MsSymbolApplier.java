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

import ghidra.app.plugin.processors.sleigh.symbol.Symbol;
import ghidra.app.util.bin.format.pdb2.pdbreader.PdbLog;
import ghidra.app.util.bin.format.pdb2.pdbreader.symbol.AbstractMsSymbol;

/**
 * Abstract class representing the applier for a specific {@link AbstractMsSymbol}.  The
 * {@link #apply()} method creates an associated {@link Symbol}, if applicable, or might
 * apply information to other {@link MsSymbolApplier AbstractMsSymbolAppliers}.
 * Methods associated with the {@link MsSymbolApplier} or derived class will
 * make fields available to the user from the {@link AbstractMsSymbol}.
 */
public abstract class MsSymbolApplier {
	protected DefaultPdbApplicator applicator;

	/**
	 * Constructor
	 * @param applicator the {@link DefaultPdbApplicator} for which we are working.
	 */
	public MsSymbolApplier(DefaultPdbApplicator applicator) {
		Objects.requireNonNull(applicator, "applicator cannot be null");
		this.applicator = applicator;
	}

	/**
	 * Puts message to {@link PdbLog} and to Msg.info()
	 * @param originator a Logger instance, "this", or YourClass.class
	 * @param message the message to display
	 */
	protected void pdbLogAndInfoMessage(Object originator, String message) {
		applicator.pdbLogAndInfoMessage(originator, message);
	}

}
