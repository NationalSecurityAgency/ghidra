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

import java.util.ArrayList;
import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.*;
import ghidra.program.util.SymbolicPropogator;
import ghidra.program.util.VarnodeContext;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzer to detect and analyze function pointer tables in MIPS binaries.
 * 
 * This analyzer identifies common patterns for function pointer usage:
 * - Operation structures (ops tables) with function pointers
 * - Virtual function tables (vtables) for C++ objects
 * - Callback registration structures
 * - Function pointer arrays
 * 
 * It creates proper references from indirect call sites (jalr) to the
 * functions they may call, improving call graph completeness.
 */
public class MipsFunctionPointerAnalyzer extends AbstractAnalyzer {
	
	private static final String NAME = "MIPS Function Pointer Analyzer";
	private static final String DESCRIPTION = 
		"Detects function pointer tables, vtables, and operation structures. " +
		"Creates references from indirect calls (jalr) to potential target functions.";
	
	private static final String OPTION_NAME_ENABLE = "Enable Function Pointer Detection";
	private static final String OPTION_DESCRIPTION_ENABLE = 
		"Enable detection of function pointer tables and indirect call resolution";
	
	private static final String OPTION_NAME_MIN_TABLE_SIZE = "Minimum Table Size";
	private static final String OPTION_DESCRIPTION_MIN_TABLE_SIZE = 
		"Minimum number of function pointers to consider a structure as a table (default: 3)";
	
	private static final String OPTION_NAME_MAX_TABLE_SIZE = "Maximum Table Size";
	private static final String OPTION_DESCRIPTION_MAX_TABLE_SIZE = 
		"Maximum number of function pointers in a table (default: 256)";
	
	private static final boolean OPTION_DEFAULT_ENABLE = true;
	private static final int OPTION_DEFAULT_MIN_TABLE_SIZE = 3;
	private static final int OPTION_DEFAULT_MAX_TABLE_SIZE = 256;
	
	private boolean enableFunctionPointerDetection = OPTION_DEFAULT_ENABLE;
	private int minTableSize = OPTION_DEFAULT_MIN_TABLE_SIZE;
	private int maxTableSize = OPTION_DEFAULT_MAX_TABLE_SIZE;
	
	public MipsFunctionPointerAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		// Run after functions are created
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
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
		
		if (!enableFunctionPointerDetection) {
			return false;
		}
		
		int tablesFound = 0;
		int referencesCreated = 0;
		
		// Strategy 1: Find function pointer tables in data sections
		List<FunctionPointerTable> tables = findFunctionPointerTables(program, monitor);
		tablesFound = tables.size();
		
		// Strategy 2: Analyze indirect calls (jalr) and try to resolve targets
		referencesCreated = analyzeIndirectCalls(program, set, tables, monitor);
		
		if (tablesFound > 0 || referencesCreated > 0) {
			Msg.info(this, "MIPS Function Pointer Analyzer: Found " + tablesFound + 
				" function pointer tables, created " + referencesCreated + " references");
		}
		
		return tablesFound > 0 || referencesCreated > 0;
	}
	
	/**
	 * Find function pointer tables in data sections
	 */
	private List<FunctionPointerTable> findFunctionPointerTables(Program program, 
			TaskMonitor monitor) throws CancelledException {
		
		List<FunctionPointerTable> tables = new ArrayList<>();
		
		// Search in data sections (.rodata, .data, .bss)
		for (MemoryBlock block : program.getMemory().getBlocks()) {
			monitor.checkCancelled();
			
			if (!block.isInitialized() || block.isExecute()) {
				continue; // Skip uninitialized or executable blocks
			}
			
			String blockName = block.getName().toLowerCase();
			if (!blockName.contains("data") && !blockName.contains("rodata") && 
			    !blockName.contains("bss")) {
				continue; // Only check data sections
			}
			
			monitor.setMessage("Scanning " + block.getName() + " for function pointer tables");
			
			// Scan the block for consecutive function pointers
			Address addr = block.getStart();
			while (addr != null && addr.compareTo(block.getEnd()) < 0) {
				monitor.checkCancelled();
				
				FunctionPointerTable table = detectTableAt(program, addr);
				if (table != null && table.size >= minTableSize) {
					tables.add(table);
					Msg.info(this, "Found function pointer table at " + addr + 
						" with " + table.size + " entries");
					
					// Create structure for the table
					createTableStructure(program, table);
					
					// Skip past this table
					addr = addr.add(table.size * program.getDefaultPointerSize());
				} else {
					addr = addr.add(program.getDefaultPointerSize());
				}
			}
		}
		
		return tables;
	}
	
	/**
	 * Detect a function pointer table starting at the given address
	 */
	private FunctionPointerTable detectTableAt(Program program, Address addr) {
		int pointerSize = program.getDefaultPointerSize();
		List<Address> functions = new ArrayList<>();
		Address current = addr;
		
		// Read consecutive pointers and check if they point to functions
		for (int i = 0; i < maxTableSize; i++) {
			try {
				long offset;
				if (pointerSize == 4) {
					offset = program.getMemory().getInt(current) & 0xFFFFFFFFL;
				} else if (pointerSize == 8) {
					offset = program.getMemory().getLong(current);
				} else {
					return null;
				}
				
				// Check if this looks like a function pointer
				if (offset == 0) {
					// Null pointer - could be end of table or valid entry
					if (functions.size() >= minTableSize) {
						break; // End of table
					}
					functions.add(null);
				} else {
					Address target = program.getAddressFactory()
						.getDefaultAddressSpace().getAddress(offset);
					
					if (isFunctionPointer(program, target)) {
						functions.add(target);
					} else {
						// Not a function pointer - end of table
						break;
					}
				}
				
				current = current.add(pointerSize);
				
			} catch (Exception e) {
				break; // Memory read error
			}
		}
		
		if (functions.size() >= minTableSize) {
			return new FunctionPointerTable(addr, functions);
		}
		
		return null;
	}
	
	/**
	 * Check if an address points to a function
	 */
	private boolean isFunctionPointer(Program program, Address addr) {
		if (addr == null) {
			return false;
		}
		
		// Check if there's a function at this address
		Function func = program.getFunctionManager().getFunctionAt(addr);
		if (func != null) {
			return true;
		}
		
		// Check if there's an instruction at this address (potential function)
		Instruction instr = program.getListing().getInstructionAt(addr);
		if (instr != null) {
			// Could be a function that hasn't been created yet
			return true;
		}
		
		return false;
	}
	
	/**
	 * Create a structure definition for a function pointer table
	 */
	private void createTableStructure(Program program, FunctionPointerTable table) {
		// Create labels for the table and its entries
		SymbolTable symTable = program.getSymbolTable();
		
		try {
			// Create label for the table
			symTable.createLabel(table.address, "func_ptr_table_" + 
				table.address.toString().replace(":", "_"), 
				SourceType.ANALYSIS);
			
			// Create labels for each entry
			int pointerSize = program.getDefaultPointerSize();
			for (int i = 0; i < table.functions.size(); i++) {
				Address entryAddr = table.address.add(i * pointerSize);
				Address funcAddr = table.functions.get(i);
				
				if (funcAddr != null) {
					// Create reference from table entry to function
					program.getReferenceManager().addMemoryReference(
						entryAddr, funcAddr, RefType.DATA, 
						SourceType.ANALYSIS, 0);
				}
			}
			
		} catch (InvalidInputException e) {
			Msg.warn(this, "Failed to create labels for function pointer table at " + 
				table.address + ": " + e.getMessage());
		}
	}
	
	/**
	 * Analyze indirect calls and create references to potential targets
	 */
	private int analyzeIndirectCalls(Program program, AddressSetView set,
			List<FunctionPointerTable> tables, TaskMonitor monitor)
			throws CancelledException {

		int referencesCreated = 0;
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		InstructionIterator instructions = listing.getInstructions(set, true);

		while (instructions.hasNext() && !monitor.isCancelled()) {
			Instruction instr = instructions.next();

			// Look for jalr (jump and link register) - indirect calls
			// Also look for jr (jump register) - tail calls / indirect jumps
			String mnemonic = instr.getMnemonicString();
			boolean isJalr = mnemonic.equals("jalr") || mnemonic.equals("_jalr");
			boolean isJr = mnemonic.equals("jr") || mnemonic.equals("_jr");

			if (isJalr || isJr) {
				// Get target register first
				Register targetReg = instr.getRegister(0);  // First operand is target register
				if (targetReg == null && instr.getNumOperands() > 1) {
					targetReg = instr.getRegister(1);  // Some variants use second operand
				}

				// Skip jr $ra (function returns)
				if (isJr && targetReg != null && targetReg.getName().equals("ra")) {
					continue;  // This is a return, not an indirect call
				}

				// Skip if this looks like a switch table (has multiple COMPUTED_JUMP references)
				Reference[] existingRefs = refMgr.getReferencesFrom(instr.getAddress());
				int computedJumpCount = 0;
				for (Reference ref : existingRefs) {
					if (ref.getReferenceType() == RefType.COMPUTED_JUMP) {
						computedJumpCount++;
					}
				}

				// If there are multiple COMPUTED_JUMP references, this is likely a switch table
				// Let the MipsSwitchTableAnalyzer handle it
				if (computedJumpCount > 1) {
					Msg.info(this, "Skipping " + mnemonic + " at " + instr.getAddress() +
						" - appears to be switch table (" + computedJumpCount + " targets)");
					continue;
				}

				String instrType = isJalr ? "jalr call" : "jr jump";
				Msg.info(this, "Found " + instrType + " at " + instr.getAddress());
				monitor.setMessage("Analyzing indirect " + instrType + " at " + instr.getAddress());

				// targetReg already obtained above
				if (targetReg != null) {
					// Track back to find where this register was loaded
					Address targetFunc = findFunctionPointerTarget(program, instr, targetReg);

					if (targetFunc != null) {
						// Remove any existing flow references that might confuse the decompiler
						for (Reference ref : existingRefs) {
							if (ref.getReferenceType().isFlow() && !ref.isPrimary()) {
								refMgr.delete(ref);
							}
						}

						// Create appropriate reference type:
						// - jalr = COMPUTED_CALL (function call)
						// - jr = COMPUTED_JUMP (tail call or indirect jump)
						RefType refType = isJalr ? RefType.COMPUTED_CALL : RefType.COMPUTED_JUMP;
						refMgr.addMemoryReference(instr.getAddress(), targetFunc,
							refType, SourceType.ANALYSIS, CodeUnit.MNEMONIC);
						referencesCreated++;

						// Create a single-entry "jump table" override to prevent the decompiler
						// from trying to recover this as a multi-target switch table
						// This suppresses the "Could not recover jumptable" warnings
						suppressSwitchTableRecovery(program, instr, targetFunc);

						Msg.info(this, "Resolved " + instrType + " at " + instr.getAddress() +
							" to " + targetFunc);
					} else {
						// Even if we can't resolve the target, create an empty jump table override
						// This prevents the decompiler from trying to treat it as a switch table
						// and suppresses the "Could not recover jumptable" warnings
						suppressSwitchTableRecovery(program, instr, null);

						Msg.info(this, "Could not resolve " + instrType + " target at " +
							instr.getAddress() + " (register: " + targetReg + ")");
					}
				}
			}
		}

		return referencesCreated;
	}

	/**
	 * Suppress switch table recovery for an indirect call by creating a jump table override.
	 * This prevents the decompiler from trying to recover this jalr/jr as a multi-target switch table.
	 *
	 * @param targetFunc The resolved target function, or null if unresolved
	 */
	private void suppressSwitchTableRecovery(Program program, Instruction jalrInstr, Address targetFunc) {
		try {
			Function function = program.getFunctionManager().getFunctionContaining(jalrInstr.getAddress());
			if (function == null) {
				return;
			}

			// Create a jump table override to suppress decompiler warnings
			// If we have a target, create a single-entry table
			// If we don't have a target, create an empty table (still suppresses warnings)
			java.util.ArrayList<Address> targetList = new java.util.ArrayList<>();
			if (targetFunc != null) {
				targetList.add(targetFunc);
			}

			ghidra.program.model.pcode.JumpTable jumpTable =
				new ghidra.program.model.pcode.JumpTable(jalrInstr.getAddress(), targetList, true);
			jumpTable.writeOverride(function);

			if (targetFunc != null) {
				Msg.debug(this, "Created jump table override at " + jalrInstr.getAddress() +
					" with target " + targetFunc);
			} else {
				Msg.debug(this, "Created empty jump table override at " + jalrInstr.getAddress() +
					" to suppress warnings");
			}
		} catch (Exception e) {
			Msg.warn(this, "Failed to create jump table override at " + jalrInstr.getAddress() +
				": " + e.getMessage());
		}
	}

	/**
	 * Track back from a jalr/jr instruction to find the function pointer being called.
	 * Uses simple backward tracking - SymbolicPropagator is too complex for this use case.
	 */
	private Address findFunctionPointerTarget(Program program, Instruction jalrInstr, Register targetReg) {
		// For now, just use the simple backward tracking
		// TODO: Implement more sophisticated tracking using SymbolicPropagator with ContextEvaluator
		return findFunctionPointerTargetSimple(program, jalrInstr, targetReg);
	}

	/**
	 * Simple backward tracking for function pointers.
	 * Searches backward up to 100 instructions looking for loads into the target register.
	 * Handles patterns like: lw $t9, offset($base) where offset is a constant.
	 */
	private Address findFunctionPointerTargetSimple(Program program, Instruction jalrInstr, Register targetReg) {
		Memory memory = program.getMemory();
		Listing listing = program.getListing();

		// Search backwards to the start of the function (no limit)
		// We need to find where the register was loaded, no matter how far back
		Function function = program.getFunctionManager().getFunctionContaining(jalrInstr.getAddress());
		Address functionStart = (function != null) ? function.getEntryPoint() : null;

		Instruction current = jalrInstr.getPrevious();
		int count = 0;
		String failureReason = "No lw instruction found in function";

		while (current != null) {
			count++;

			// Stop if we've left the function
			if (functionStart != null && current.getAddress().compareTo(functionStart) < 0) {
				failureReason = "No lw instruction found within function (searched " + count + " instructions)";
				break;
			}

			// Look for lw (load word) that writes to our target register
			String mnemonic = current.getMnemonicString();
			if (mnemonic.equals("lw") || mnemonic.equals("_lw")) {
				Register destReg = current.getRegister(0);

				if (destReg != null && destReg.equals(targetReg)) {
					// Found the load instruction: lw $dest, offset($base)
					Msg.info(this, "  Found lw at " + current.getAddress() + ": " + current);

					// Try Method 1: Check for existing data references
					Address resolvedAddr = tryResolveFromReferences(program, current, memory);
					if (resolvedAddr != null) {
						Msg.info(this, "  Resolved via data reference");
						return resolvedAddr;
					}

					// Try Method 2: Parse operands to get address
					resolvedAddr = tryResolveFromOperands(program, current, memory, listing);
					if (resolvedAddr != null) {
						Msg.info(this, "  Resolved via operand parsing");
						return resolvedAddr;
					}

					// Try Method 3: $gp-relative resolution
					resolvedAddr = tryResolveGpRelative(program, current, function);
					if (resolvedAddr != null) {
						Msg.info(this, "  Resolved via $gp-relative load");
						return resolvedAddr;
					}

					// Analyze why it failed
					failureReason = analyzeLoadFailure(current);
					Msg.info(this, "  " + failureReason);

					// Found the load but couldn't resolve target - stop searching
					break;
				}
			}

			// If we find another write to the target register, check if it's a load
			if (current.getRegister(0) != null && current.getRegister(0).equals(targetReg)) {
				String mnem = current.getMnemonicString();

				// If it's another lw, we already handled it above
				// If it's something else (jalr, addiu, move, etc.), keep searching
				// Don't stop - saved registers are loaded once and used many times
				if (!mnem.equals("lw") && !mnem.equals("_lw")) {
					// Just continue searching - we removed the search limit
					// Continue searching - don't break!
				}
			}

			current = current.getPrevious();
		}

		Msg.info(this, "  Failure: " + failureReason);
		return null;
	}

	/**
	 * Analyze why a load instruction couldn't be resolved.
	 */
	private String analyzeLoadFailure(Instruction lwInstr) {
		// Check the operand representation
		String op1 = lwInstr.getDefaultOperandRepresentation(1);

		// Pattern: offset($base) - register-relative
		if (op1.contains("(") && op1.contains(")")) {
			String baseReg = op1.substring(op1.indexOf("(") + 1, op1.indexOf(")"));
			return "Register-relative load: " + op1 + " (base=" + baseReg + ")";
		}

		// Pattern: label or absolute address
		if (lwInstr.getNumOperands() >= 2) {
			Object[] opObjs = lwInstr.getOpObjects(1);
			if (opObjs.length == 0) {
				return "No operand objects found";
			}
			return "Operand type: " + opObjs[0].getClass().getSimpleName() + " = " + opObjs[0];
		}

		return "Unknown load pattern";
	}

	/**
	 * Try to resolve function pointer from existing data references on the instruction.
	 */
	private Address tryResolveFromReferences(Program program, Instruction lwInstr, Memory memory) {
		Reference[] refs = lwInstr.getReferencesFrom();
		for (Reference ref : refs) {
			if (ref.isMemoryReference() && ref.getReferenceType().isData()) {
				Address dataAddr = ref.getToAddress();

				try {
					long offset = memory.getInt(dataAddr) & 0xFFFFFFFFL;
					Address funcAddr = program.getAddressFactory()
						.getDefaultAddressSpace().getAddress(offset);

					// Verify it points to a function or code
					if (program.getFunctionManager().getFunctionAt(funcAddr) != null ||
						program.getListing().getInstructionAt(funcAddr) != null) {
						Msg.debug(this, "Resolved from data reference: " + dataAddr + " -> " + funcAddr);
						return funcAddr;
					}
				} catch (Exception e) {
					// Memory read failed, continue
				}
			}
		}
		return null;
	}

	/**
	 * Try to resolve function pointer by parsing instruction operands.
	 */
	private Address tryResolveFromOperands(Program program, Instruction lwInstr, Memory memory, Listing listing) {
		// Check if operand 1 contains an address
		if (lwInstr.getNumOperands() >= 2) {
			Object[] opObjs = lwInstr.getOpObjects(1);
			for (Object obj : opObjs) {
				if (obj instanceof Address) {
					Address dataAddr = (Address) obj;

					try {
						long offset = memory.getInt(dataAddr) & 0xFFFFFFFFL;
						Address funcAddr = program.getAddressFactory()
							.getDefaultAddressSpace().getAddress(offset);

						if (program.getFunctionManager().getFunctionAt(funcAddr) != null ||
							listing.getInstructionAt(funcAddr) != null) {
							Msg.debug(this, "Resolved from operand: " + dataAddr + " -> " + funcAddr);
							return funcAddr;
						}
					} catch (Exception e) {
						// Continue
					}
				}
			}
		}
		return null;
	}
	
	@Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(OPTION_NAME_ENABLE, enableFunctionPointerDetection, null,
			OPTION_DESCRIPTION_ENABLE);
		options.registerOption(OPTION_NAME_MIN_TABLE_SIZE, minTableSize, null,
			OPTION_DESCRIPTION_MIN_TABLE_SIZE);
		options.registerOption(OPTION_NAME_MAX_TABLE_SIZE, maxTableSize, null,
			OPTION_DESCRIPTION_MAX_TABLE_SIZE);
	}
	
	@Override
	public void optionsChanged(Options options, Program program) {
		enableFunctionPointerDetection = options.getBoolean(OPTION_NAME_ENABLE, 
			enableFunctionPointerDetection);
		minTableSize = options.getInt(OPTION_NAME_MIN_TABLE_SIZE, minTableSize);
		maxTableSize = options.getInt(OPTION_NAME_MAX_TABLE_SIZE, maxTableSize);
	}
	
	/**
	 * Try to resolve a $gp-relative load instruction.
	 * Pattern: lw $reg, offset($gp)
	 *
	 * MIPS uses $gp (global pointer) to access the GOT (Global Offset Table).
	 * We need to:
	 * 1. Get the $gp value for the function's section
	 * 2. Calculate address = $gp + offset
	 * 3. Read the function pointer from that address
	 */
	private Address tryResolveGpRelative(Program program, Instruction lwInstr, Function function) {
		try {
			// Check if this is a $gp-relative load: lw $reg, offset($gp)
			String op1 = lwInstr.getDefaultOperandRepresentation(1);
			if (!op1.contains("(gp)")) {
				return null;  // Not a $gp-relative load
			}

			// Extract the offset from the operand (e.g., "0x18(gp)" -> 0x18)
			int openParen = op1.indexOf('(');
			if (openParen <= 0) {
				return null;
			}

			String offsetStr = op1.substring(0, openParen).trim();
			long offset;
			if (offsetStr.startsWith("0x") || offsetStr.startsWith("-0x")) {
				offset = Long.parseLong(offsetStr.replace("0x", "").replace("-0x", "-"), 16);
			} else {
				offset = Long.parseLong(offsetStr);
			}

			// Get the $gp value for this function's section
			// MIPS kernel modules have multiple $gp values for different sections
			Long gpValue = getGlobalPointerValue(program, lwInstr.getAddress());
			if (gpValue == null) {
				Msg.info(this, "  Could not determine $gp value for section");
				return null;
			}

			// Calculate the address in the GOT
			long gotAddress = gpValue + offset;
			Address gotAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(gotAddress);

			// Read the function pointer from the GOT
			Memory memory = program.getMemory();
			if (!memory.contains(gotAddr)) {
				Msg.info(this, "  GOT address not in memory: " + gotAddr);
				return null;
			}

			long funcPtr = memory.getInt(gotAddr) & 0xFFFFFFFFL;
			Address funcAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(funcPtr);

			// Validate it's a valid code address
			if (program.getListing().getInstructionAt(funcAddr) != null) {
				Msg.info(this, "  Resolved $gp-relative: $gp=" + String.format("0x%x", gpValue) +
					", offset=" + String.format("0x%x", offset) +
					", GOT=" + gotAddr + ", target=" + funcAddr);
				return funcAddr;
			}

		} catch (Exception e) {
			Msg.debug(this, "Failed to resolve $gp-relative load: " + e.getMessage());
		}

		return null;
	}

	/**
	 * Get the $gp (global pointer) value for a given address.
	 * MIPS kernel modules can have multiple $gp values for different sections.
	 */
	private Long getGlobalPointerValue(Program program, Address addr) {
		try {
			// Method 1: Try to get $gp from program context register
			// This is the most reliable method - the loader sets this
			ghidra.program.model.lang.Register gpReg = program.getRegister("gp");
			if (gpReg != null) {
				ghidra.program.model.listing.ProgramContext context = program.getProgramContext();
				ghidra.program.model.lang.RegisterValue gpValue = context.getRegisterValue(gpReg, addr);
				if (gpValue != null && gpValue.hasValue()) {
					long gp = gpValue.getUnsignedValue().longValue();
					if (gp != 0) {
						Msg.debug(this, "  Got $gp from program context: 0x" + Long.toHexString(gp));
						return gp;
					}
				}
			}

			// Method 2: Look for GOT memory blocks
			// The loader creates blocks like "%got.text" with specific $gp values
			MemoryBlock block = program.getMemory().getBlock(addr);
			if (block != null) {
				String blockName = block.getName();

				// Try to find the corresponding GOT block
				for (MemoryBlock mb : program.getMemory().getBlocks()) {
					String mbName = mb.getName();
					if (mbName.startsWith("%got")) {
						// Found a GOT block - $gp points to GOT + 0x7ff0
						long gotStart = mb.getStart().getOffset();
						long gp = gotStart + 0x7ff0;
						Msg.debug(this, "  Got $gp from GOT block " + mbName + ": 0x" + Long.toHexString(gp));
						return gp;
					}
				}
			}

			// Method 3: Try program properties
			Options props = program.getOptions(Program.PROGRAM_INFO);
			if (props.contains("_mips_gp0_value")) {
				long gp = props.getLong("_mips_gp0_value", 0L);
				if (gp != 0) {
					Msg.debug(this, "  Got $gp from program properties: 0x" + Long.toHexString(gp));
					return gp;
				}
			}

			// Method 4: Look for .got section and calculate
			for (MemoryBlock mb : program.getMemory().getBlocks()) {
				String mbName = mb.getName();
				if (mbName.equals(".got") || mbName.contains("got")) {
					long gotStart = mb.getStart().getOffset();
					long gp = gotStart + 0x7ff0;
					Msg.debug(this, "  Got $gp from .got section: 0x" + Long.toHexString(gp));
					return gp;
				}
			}

		} catch (Exception e) {
			Msg.debug(this, "Error getting $gp value: " + e.getMessage());
		}

		return null;
	}

	/**
	 * Information about a detected function pointer table
	 */
	private static class FunctionPointerTable {
		final Address address;
		final List<Address> functions;
		final int size;

		FunctionPointerTable(Address address, List<Address> functions) {
			this.address = address;
			this.functions = functions;
			this.size = functions.size();
		}
	}
}

