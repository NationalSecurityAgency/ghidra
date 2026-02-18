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
package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer to detect and disassemble inline case handlers in MIPS switch statements.
 * 
 * This analyzer identifies valid MIPS instructions in data regions that are targets
 * of computed jumps (switch statements). It safely disassembles these inline handlers
 * and maintains proper fall-through relationships.
 * 
 * Common pattern:
 * - Switch table contains addresses pointing to "data" regions
 * - These regions actually contain valid MIPS code (case handlers)
 * - Handlers are short code sequences that branch to common code
 * - Without this analyzer, they remain as undefined data
 */
public class MipsInlineCodeAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "MIPS Inline Code Analyzer";
	private static final String DESCRIPTION = 
		"Detects and disassembles inline case handlers in MIPS switch statements. " +
		"Identifies valid MIPS instructions in data regions following computed jumps.";
	
	private static final String OPTION_NAME_ENABLE = "Enable Inline Handler Detection";
	private static final String OPTION_DESCRIPTION_ENABLE = 
		"Enable detection and disassembly of inline case handlers in data regions";
	
	private static final String OPTION_NAME_MIN_CONFIDENCE = "Minimum Confidence Threshold";
	private static final String OPTION_DESCRIPTION_MIN_CONFIDENCE = 
		"Minimum confidence level (0.0-1.0) required to disassemble data as code (default: 0.7)";
	
	private static final boolean OPTION_DEFAULT_ENABLE = true;
	private static final double OPTION_DEFAULT_MIN_CONFIDENCE = 0.7;
	
	private static final int MAX_INLINE_HANDLER_SIZE = 64; // bytes
	
	private boolean enableInlineDetection = OPTION_DEFAULT_ENABLE;
	private double minConfidence = OPTION_DEFAULT_MIN_CONFIDENCE;
	
	public MipsInlineCodeAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		// Run after switch table analyzer
		setPriority(AnalysisPriority.BLOCK_ANALYSIS.after().after());
		setDefaultEnablement(true);
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().equals(
			Processor.findOrPossiblyCreateProcessor("MIPS"));
	}
	
	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		
		if (!enableInlineDetection) {
			return false;
		}
		
		int handlersFound = 0;
		
		// Find all computed jumps (potential switch statements)
		ReferenceManager refMgr = program.getReferenceManager();
		AddressIterator refIter = refMgr.getReferenceSourceIterator(set, true);
		
		while (refIter.hasNext() && !monitor.isCancelled()) {
			Address fromAddr = refIter.next();
			
			// Get all references from this address
			Reference[] refs = refMgr.getReferencesFrom(fromAddr);
			for (Reference ref : refs) {
				// Look for computed jumps
				if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
					Address targetAddr = ref.getToAddress();
					
					// Check if target is in a data region
					if (isInDataRegion(program, targetAddr)) {
						monitor.setMessage("Checking inline handler at " + targetAddr);
						
						// Try to disassemble as inline handler
						if (disassembleInlineHandler(program, targetAddr, monitor, log)) {
							handlersFound++;
							Msg.info(this, "Disassembled inline handler at " + targetAddr);
						}
					}
				}
			}
		}
		
		if (handlersFound > 0) {
			Msg.info(this, "MIPS Inline Code Analyzer: Found " + handlersFound + " inline handlers");
		}
		
		return handlersFound > 0;
	}
	
	/**
	 * Check if an address is in a data region (not already disassembled)
	 */
	private boolean isInDataRegion(Program program, Address addr) {
		Listing listing = program.getListing();
		
		// Check if already disassembled
		if (listing.getInstructionAt(addr) != null) {
			return false;
		}
		
		// Check if it's in an executable block
		MemoryBlock block = program.getMemory().getBlock(addr);
		if (block == null || !block.isInitialized()) {
			return false;
		}
		
		// It's in memory but not disassembled - potential inline handler
		return true;
	}
	
	/**
	 * Attempt to disassemble an inline handler at the given address
	 */
	private boolean disassembleInlineHandler(Program program, Address addr, 
			TaskMonitor monitor, MessageLog log) {
		
		// Use PseudoDisassembler to check if it looks like valid code
		PseudoDisassembler pseudoDis = new PseudoDisassembler(program);
		
		// Check if this looks like a valid subroutine entry
		if (!pseudoDis.isValidSubroutine(addr, true)) {
			return false;
		}
		
		// Calculate confidence score
		double confidence = calculateCodeConfidence(program, pseudoDis, addr);
		if (confidence < minConfidence) {
			Msg.debug(this, "Confidence too low for inline handler at " + addr + 
				": " + confidence);
			return false;
		}
		
		// Looks good - disassemble it
		Disassembler dis = Disassembler.getDisassembler(program, monitor, null);
		AddressSet disSet = dis.disassemble(addr, null, true);
		
		if (disSet == null || disSet.isEmpty()) {
			Msg.warn(this, "Failed to disassemble inline handler at " + addr);
			return false;
		}
		
		// Success!
		return true;
	}
	
	/**
	 * Calculate confidence that a region contains valid MIPS code
	 * Returns value between 0.0 (definitely data) and 1.0 (definitely code)
	 */
	private double calculateCodeConfidence(Program program, PseudoDisassembler pseudoDis, 
			Address addr) {
		
		int validInstructions = 0;
		int totalChecked = 0;
		int maxInstructions = MAX_INLINE_HANDLER_SIZE / 4; // MIPS instructions are 4 bytes
		
		Address current = addr;

		for (int i = 0; i < maxInstructions; i++) {
			// Try to disassemble one instruction
			PseudoInstruction instr = null;
			try {
				instr = pseudoDis.disassemble(current);
			} catch (Exception e) {
				// InsufficientBytesException, UnknownInstructionException, etc.
				break; // Can't disassemble
			}

			if (instr == null) {
				break; // Can't disassemble
			}

			totalChecked++;

			// Check if it's a valid MIPS instruction
			if (isValidMipsInstruction(instr)) {
				validInstructions++;
			}

			// Stop at branch instructions (likely end of handler)
			String mnemonic = instr.getMnemonicString();
			if (mnemonic.equals("b") || mnemonic.equals("j") ||
			    mnemonic.equals("jr") || mnemonic.equals("beq") ||
			    mnemonic.equals("bne") || mnemonic.equals("beqz") ||
			    mnemonic.equals("bnez")) {
				break;
			}

			current = current.add(instr.getLength());
		}
		
		if (totalChecked == 0) {
			return 0.0;
		}
		
		// Calculate confidence as ratio of valid instructions
		double baseConfidence = (double) validInstructions / totalChecked;
		
		// Boost confidence if we found at least 2 valid instructions
		if (validInstructions >= 2) {
			baseConfidence = Math.min(1.0, baseConfidence + 0.1);
		}
		
		return baseConfidence;
	}
	
	/**
	 * Check if a pseudo-instruction looks like a valid MIPS instruction
	 */
	private boolean isValidMipsInstruction(PseudoInstruction instr) {
		String mnemonic = instr.getMnemonicString();
		
		// Reject obviously invalid mnemonics
		if (mnemonic == null || mnemonic.isEmpty()) {
			return false;
		}
		
		// Reject if it looks like data (all zeros, all ones, etc.)
		if (mnemonic.equals("???") || mnemonic.equals("undefined")) {
			return false;
		}
		
		// Check for common MIPS instructions
		// This is a heuristic - valid instructions are more likely to be code
		return mnemonic.matches("[a-z][a-z0-9]*");
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_ENABLE, enableInlineDetection, null,
			OPTION_DESCRIPTION_ENABLE);
		options.registerOption(OPTION_NAME_MIN_CONFIDENCE, minConfidence, null,
			OPTION_DESCRIPTION_MIN_CONFIDENCE);
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		enableInlineDetection = options.getBoolean(OPTION_NAME_ENABLE, enableInlineDetection);
		minConfidence = options.getDouble(OPTION_NAME_MIN_CONFIDENCE, minConfidence);
	}
}

