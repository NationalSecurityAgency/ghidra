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
package ghidra.program.util;

import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * <code>LanguagePostUpgradeInstructionHandler</code> provides an abstract implementation 
 * of a post language-upgrade instruction modification handler.  The Simple Language Translator
 * facilitates the specification of such a handler implementation within a language 
 * translator specification file using the <i>post_upgrade_handler</i> element.
 * Following a major-version language upgrade, the last translator invoked is given an
 * opportunity to perform additional instruction modifications on the entire program.
 */
public abstract class LanguagePostUpgradeInstructionHandler {

	protected final Program program;

	private Disassembler disassembler;

	/**
	 * Constructor
	 * @param program
	 */
	public LanguagePostUpgradeInstructionHandler(Program program) {
		this.program = program;
	}

	/**
	 * Get disassembler for the current program
	 * @return disassembler instance
	 */
	protected Disassembler getDisassembler() {
		if (disassembler == null) {
			disassembler = Disassembler.getDisassembler(program, TaskMonitor.DUMMY, null);
		}
		return disassembler;
	}

	/**
	 * Invoked after Program language upgrade has completed.  
	 * Implementation of this method permits the final re-disassembled program to be
	 * examined/modified to address more complex language upgrades.  This method will only be 
	 * invoked on the latest translator, which means all complex multi-version post-upgrade
	 * concerns must factor in the complete language transition.  The program's language 
	 * information will still reflect the original pre-upgrade state, and if the program is
	 * undergoing a schema version upgrade as well, certain complex upgrades may not
	 * have been completed (e.g., Function and Variable changes).  Program modifications should
	 * be restricted to instruction and instruction context changes only.
	 * @param oldLanguage the oldest language involved in the current upgrade translation
	 * (this is passed since this is the only fixup invocation which must handle the any
	 * relevant fixup complexities when transitioning from the specified oldLanguage).
	 * @param monitor task monitor
	 * @throws CancelledException if upgrade cancelled
	 */
	public abstract void fixupInstructions(Language oldLanguage, TaskMonitor monitor)
			throws CancelledException;

	/**
	 * Repair the context and re-disassemble the instruction at the specified address.
	 * @param addr instruction address
	 * @param contextValue new context value
	 * @param mergeContext if true, the specified context value will be merged with the existing 
	 * context at the specified address, otherwise the existing value will be replaced.
	 */
	protected void modifySingleInstructionContext(Address addr,
			RegisterValue contextValue, boolean mergeContext) {

		Register baseReg = contextValue.getRegister().getBaseRegister();
		if (!baseReg.isProcessorContext()) {
			throw new IllegalArgumentException("Invalid context register: " + baseReg.getName());
		}
		Listing listing = program.getListing();
		if (mergeContext) {
			ProgramContext programContext = program.getProgramContext();
			RegisterValue oldRegisterValue = programContext.getRegisterValue(baseReg, addr);
			if (oldRegisterValue != null) {
				contextValue = oldRegisterValue.combineValues(contextValue);
			}
		}
		listing.clearCodeUnits(addr, addr, true);
		getDisassembler().disassemble(addr, null, contextValue, true);
	}
}
