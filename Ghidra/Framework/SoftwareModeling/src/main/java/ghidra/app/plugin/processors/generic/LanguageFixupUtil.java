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
package ghidra.app.plugin.processors.generic;

import java.util.*;

import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.AddressLabelInfo;
import ghidra.program.model.lang.Language;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockException;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * {@link LanguageFixupUtil} provides utility method intended for internal language upgrade
 * situations.
 */
public class LanguageFixupUtil {

	/**
	 * Apply pspec defined memory blocks and default symbols which are considered safe and 
	 * generally required.  Reconciling symbols is limited to those symbols contained within
	 * processor defined memory blocks which are not within either the default code or data spaces.
	 * @param programDB target program
	 * @param monitor task monitor
	 * @throws CancelledException if fixup task is cancelled
	 */
	public static void applyPSpecFixups(ProgramDB programDB, TaskMonitor monitor)
			throws CancelledException {

		try {
			Language language = programDB.getLanguage();
			ProgramDataTypeManager dtm = programDB.getDataTypeManager();

			AddressSpace defaultSpace = language.getDefaultSpace();
			AddressSpace defaultDataSpace = language.getDefaultDataSpace();

			// Create or fixup processor defined memory blocks
			// NOTE: Additional translator capability required if block removal is required which 
			// would likely remove any IMPORTED symbols contained within its bounds
			AddressSet processorDefinedBlockSet = new AddressSet();

			// Define address set which identifies processor define blocks which are safe to scrub 
			// of old imported symbols.
			AddressSet processorDefinedSafeBlockSet = new AddressSet();

			for (MemoryBlockDefinition defaultMemoryBlockDef : language.getDefaultMemoryBlocks()) {
				monitor.checkCancelled();
				try {
					MemoryBlock block = defaultMemoryBlockDef.fixupBlock(programDB);
					AddressRange blockRange = block.getAddressRange();
					processorDefinedBlockSet.add(blockRange);
					AddressSpace space = block.getStart().getAddressSpace();
					if (!space.equals(defaultSpace) && !space.equals(defaultDataSpace)) {
						processorDefinedSafeBlockSet.add(blockRange);
					}
				}
				catch (MemoryBlockException e) {
					Msg.error(LanguageFixupUtil.class,
						"Failed to create or fixup processor defined memory block '" +
							defaultMemoryBlockDef.getBlockName() + "': " + e.getMessage());
				}
				catch (LockException e) {
					throw new RuntimeException(e);  // upgrades require exclusive access
				}
			}

			// Create default symbols within processorDefinedBlockSet if missing.
			// The goodSymbols set is used to record all processor defined symbols to assist cleanup
			SymbolManager symbolTable = programDB.getSymbolTable();
			HashSet<Symbol> goodSymbols = new HashSet<>();
			for (AddressLabelInfo labelInfo : language.getDefaultSymbols()) {

				String name = labelInfo.getLabel();
				Address addr = labelInfo.getAddress();

				// NOTE: For now we only add symbols which are defined within processor-defined blocks
				if (!processorDefinedBlockSet.contains(addr)) {
					continue;
				}

				// Check all symbols within processor-defined blocks
				Symbol existingSymbol = null;
				for (Symbol s : symbolTable.getGlobalSymbols(name)) {
					monitor.checkCancelled();
					if (s.getSymbolType() != SymbolType.LABEL) {
						continue;
					}
					if (addr.equals(s.getAddress())) {
						// Keep existing label which matches spec
						existingSymbol = s;
						goodSymbols.add(s);
					}
					else if (s.getSource() == SourceType.IMPORTED &&
						processorDefinedBlockSet.contains(s.getAddress())) {
						// Remove label from its old location 
						s.delete();
					}
				}
				if (existingSymbol == null) {
					// Add missing label
					try {
						Symbol s = symbolTable.createLabel(addr, name, null, SourceType.IMPORTED);
						goodSymbols.add(s);
					}
					catch (InvalidInputException e) {
						throw new AssertException(e); // unexpected
					}
				}
			}

			// Remove all symbols within processor defined blocks which are no longer defined.
			// This is restricted to safe address spaces since loader may have imported other symbols
			// which we do not want to delete.  We collect symbols first to avoid concurent 
			// modification concerns.
			List<Symbol> deleteSet = new ArrayList<>(); // defered delete to avoid iterator resets
			for (Symbol s : symbolTable.getSymbols(processorDefinedSafeBlockSet, SymbolType.LABEL,
				true)) {
				monitor.checkCancelled();
				if (s.getSource() == SourceType.IMPORTED && !goodSymbols.contains(s)) {
					deleteSet.add(s);
				}
			}
			for (Symbol s : deleteSet) {
				monitor.checkCancelled();
				s.delete();
			}
		}
		catch (UnsupportedOperationException e) {
			// skip
		}
	}

}
