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
/*
 * OperandReferenceAnalyzer.java
 *
 * Created on Aug 5, 2003
 */
package ghidra.app.plugin.core.analysis;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.cmd.data.CreateStringCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.CreateThunkFunctionCmd;
import ghidra.app.plugin.core.disassembler.AddressTable;
import ghidra.app.plugin.core.function.FunctionAnalyzer;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.PeLoader;
import ghidra.framework.cmd.*;
import ghidra.framework.options.Options;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Check operand references to memory locations looking for
 * Data
 *
 */
public class OperandReferenceAnalyzer extends AbstractAnalyzer {
	private static final String NAME = "Reference";
	private static final String DESCRIPTION = "Analyzes data referenced by instructions.";

	private final static String OPTION_NAME_ASCII = "Ascii String References";
	private final static String OPTION_NAME_UNICODE = "Unicode String References";
	private final static String OPTION_NAME_ALIGN_STRINGS = "Align End of Strings";
	private final static String OPTION_NAME_MIN_STRING_LENGTH = "Minimum String Length";
	private final static String OPTION_NAME_POINTER = "References to Pointers";
	private final static String OPTION_NAME_RELOCATION_GUIDE = "Relocation Table Guide";
	private final static String OPTION_NAME_SUBROUTINE = "Subroutine References";
	private final static String OPTION_NAME_ADDRESS_TABLE = "Create Address Tables";
	private final static String OPTION_NAME_SWITCH = "Switch Table References";
	private final static String OPTION_NAME_SWITCH_ALIGNMENT = "Address Table Alignment";
	private final static String OPTION_NAME_MINIMUM_TABLE_SIZE = "Address Table Minimum Size";
	private final static String OPTION_NAME_RESPECT_EXECUTE_FLAG = "Respect Execute Flag";

	private static final String OPTION_DESCRIPTION_ASCII =
		"Select this check box to create an ascii string if there is a reference to it.";
	private static final String OPTION_DESCRIPTION_UNICODE =
		"Select this check box to create a unicode string if there is a reference to it.";
	private static final String OPTION_DESCRIPTION_ALIGN_STRINGS =
		"Select this check box to align string length to the processors alignment if the trailing bytes are '0's";
	private static final String OPTION_DESCRIPTION_MIN_STRING_LENGTH =
		"Minimum number of bytes for a string to be valid.";
	private static final String OPTION_DESCRIPTION_POINTER =
		"Select this check box to create pointers if there is a reference to it.";
	private static final String OPTION_DESCRIPTION_RELOCATION_GUIDE =
		"Select this check box to use relocation table entries to guide pointer analysis.";
	private static final String OPTION_DESCRIPTION_SUBROUTINE =
		"Select this check box to bookmark code that is a valid subroutine code flow and disassemble there.\nNOTE: this no longer makes a function.";
	private static final String OPTION_DESCRIPTION_ADDRESS_TABLE =
		"Select this check box to create an address table if there is a reference to it.";
	private static final String OPTION_DESCRIPTION_SWITCH =
		"Select this check box to create a switch table if there is a reference to it.";
	private static final String OPTION_DESCRIPTION_SWITCH_ALIGNMENT =
		"Align Address Tables on this number of bytes.";
	private static final String OPTION_DESCRIPTION_MINIMUM_TABLE_SIZE =
		"Minimum run of valid pointers to be considered an address table.";
	private static final String OPTION_DESCRIPTION_RESPECT_EXECUTE_FLAG =
		"Respect Execute flag on memory blocks when checking entry points for code.";

	private final static boolean OPTION_DEFAULT_ASCII_ENABLED = true;
	private final static boolean OPTION_DEFAULT_UNICODE_ENABLED = true;
	private final static boolean OPTION_DEFAULT_ALIGN_STRINGS_ENABLED = false;
	private final static int OPTION_DEFAULT_MIN_STRING_LENGTH = 5;
	private final static boolean OPTION_DEFAULT_POINTER_ENABLED = true;
	private final static boolean OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED = true;
	private final static boolean OPTION_DEFAULT_SUBROUTINES_ENABLED = true;
	private final static boolean OPTION_DEFAULT_ADDRESS_TABLES_ENABLED = true;
	private final static boolean OPTION_DEFAULT_SWITCH_TABLE_ENABLED = false;
	private final static int OPTION_DEFAULT_SWITCH_TABLE_ALIGNMENT = 1;
	private final static boolean OPTION_DEFAULT_RESPECT_EXECUTE_ENABLED = true;

	private static final int MINIMUM_POTENTIAL_TABLE_SIZE = 3;
	private final static int NOTIFICATION_INTERVAL = 256;
	private final static int MAX_NEG_ENTRIES = 32;

	private boolean asciiEnabled = OPTION_DEFAULT_ASCII_ENABLED;
	private boolean unicodeEnabled = OPTION_DEFAULT_UNICODE_ENABLED;
	private boolean alignStringsEnabled = OPTION_DEFAULT_ALIGN_STRINGS_ENABLED;
	private int minStringLength = OPTION_DEFAULT_MIN_STRING_LENGTH;
	private boolean pointerEnabled = OPTION_DEFAULT_POINTER_ENABLED;
	private boolean relocationGuideEnabled = OPTION_DEFAULT_RELOCATION_GUIDE_ENABLED;
	private boolean subroutinesEnabled = OPTION_DEFAULT_SUBROUTINES_ENABLED;
	private boolean addressTablesEnabled = OPTION_DEFAULT_ADDRESS_TABLES_ENABLED;
	private int minimumAddressTableSize = -1;
	private boolean switchTableEnabled = OPTION_DEFAULT_SWITCH_TABLE_ENABLED;
	private int switchTableAlignment = OPTION_DEFAULT_SWITCH_TABLE_ALIGNMENT;

	private boolean newCodeFound = false;
	private int processorAlignment = 1;
	private MemoryBlock externalBlock;
	private boolean respectExecuteFlags = true;

	public OperandReferenceAnalyzer() {
		this(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
	}

	public OperandReferenceAnalyzer(String name, String description, AnalyzerType analyzerType) {
		super(name, description, analyzerType);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS);
	}

	@Override
	public boolean canAnalyze(Program program) {
		// segmented addresses can't tell the segment for an address from just the two byte offset
		AddressSpace defaultAddressSpace = program.getAddressFactory().getDefaultAddressSpace();
		if (defaultAddressSpace instanceof SegmentedAddressSpace) {
			pointerEnabled = false;
			addressTablesEnabled = false;
		}

		// only analyze programs with address spaces > 16 bits
		int bitSize = defaultAddressSpace.getSize();
		return bitSize > 16;
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		if (minimumAddressTableSize == -1) {
			calculateMinimumAddressTableSize(program);
		}

		addressTablesEnabled = PeLoader.PE_NAME.equals(program.getExecutableFormat());

		if (minimumAddressTableSize == -1) {
			calculateMinimumAddressTableSize(program);
		}

		//switchTableEnabled =
		//	program.getLanguage().getPropertyAsBoolean(
		//		GhidraLanguagePropertyKeys.USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES, false);
		return true;
	}

	private void calculateMinimumAddressTableSize(Program program) {
		minimumAddressTableSize =
			AddressTable.getThresholdRunOfValidPointers(program, AddressTable.BILLION_CASES);

		if (minimumAddressTableSize < 2) {
			minimumAddressTableSize = 2;
		}
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		if (!asciiEnabled && !unicodeEnabled && !subroutinesEnabled) {
			String message = "ASCII, Unicode, and Subroutines are all disabled.";
			log.appendMsg(getName(), message);
			log.setStatus(message);

			return false;
		}

		processorAlignment = program.getLanguage().getInstructionAlignment();

		externalBlock = program.getMemory().getBlock(MemoryBlock.EXTERNAL_BLOCK_NAME);

		newCodeFound = false;
		int count = NOTIFICATION_INTERVAL;
		long initial_count = set.getNumAddresses();
		monitor.initialize(initial_count);
		AddressSet leftSet = new AddressSet(set);

		// Iterate over all references within the new address set
		//   Evaluate each reference
		//
		Listing listing = program.getListing();
		Memory memory = program.getMemory();

		AddressSet executeSet = getExecuteSet(memory);
		if (!respectExecuteFlags) {
			executeSet = null;
		}
		AddressSet ignoreNewPointers = new AddressSet();

		AddressIterator iter = program.getReferenceManager().getReferenceSourceIterator(set, true);
		PseudoDisassembler pdis = new PseudoDisassembler(program);
		pdis.setRespectExecuteFlag(respectExecuteFlags);
		monitor.setMessage("Analyze Operand References " + set.getMinAddress());

		AddressSet disTargets = new AddressSet();
		AddressSet foundCodeBookmarkLocations = new AddressSet();

		AddressSet doneSubTest = new AddressSet();

		// set of targets already checked.  Don't do them again.
		AddressSet checkedTargets = new AddressSet();

		while (iter.hasNext() && !newCodeFound) {
			monitor.checkCanceled();

			Address addr = iter.next();

			count++;
			if (count > NOTIFICATION_INTERVAL) {
				leftSet.deleteRange(leftSet.getMinAddress(), addr);
				monitor.setProgress(initial_count - leftSet.getNumAddresses());
				monitor.setMessage("Analyze OpRefs : " + addr);
				count = 0;
			}

			if (ignoreNewPointers.contains(addr)) {
				continue;
			}
			CodeUnit cu = listing.getCodeUnitContaining(addr);
			if (cu == null) {
				continue;
			}
//TODO: should really make a list of places to disassemble code
//      and another list of places that read/write the contents of
//      the memory location.  Then at the end schedule disassembly
//      of those places that are not on the read/write list.

			// check out any memory references
			//   for code references or valid strings
			//

			Reference[] memRefs = cu.getReferencesFrom();
			// ignore any references coming out of here, they are all about to be processed
			ignoreNewPointers.addRange(cu.getMinAddress(), cu.getMaxAddress());
			for (int m = 0; m < memRefs.length && !monitor.isCancelled(); m++) {
				Reference reference = memRefs[m];
				Address target = reference.getToAddress();

				RefType memRefType = reference.getReferenceType();
				if (memRefType.isFlow() && !memRefType.isIndirect() && !(cu instanceof Data)) {
					if (memRefType.isCall() && memRefType.isComputed()) {
						Function func = listing.getFunctionAt(target);
						if (func == null) {
							// better make sure function analyzer sees this...
							// TODO: this is probably too much callusion.
							FunctionAnalyzer anal = new FunctionAnalyzer();
							AddressSet funcSet = new AddressSet(reference.getFromAddress());
							mgr.scheduleOneTimeAnalysis(anal, funcSet);
						}
					}

					if (memRefType.isJump()) {
						checkForExternalJump(program, reference, monitor);
					}

					Instruction instr = (Instruction) cu;

					// if is a computed jump reference, this could be a thunk
					if (memRefType.isComputed() && memRefs.length <= 2) {
						if (memRefType.isCall() &&
							instr.getFlowType() != RefType.COMPUTED_CALL_TERMINATOR) {
							continue;
						}
						FunctionManager funcMgr = program.getFunctionManager();
						Function func = funcMgr.getFunctionContaining(reference.getFromAddress());
						if (func != null) {
							// this could be a thunk, force a re-analysis.
							// single instruction with a computed jump on it.
							//    New information from the thunked function (noreturn, callfixup, etc...)
							//    may affect callers to the function, so tell analyzers about it.
							// TODO: this should be done by the Auto Thunking mechanisms...
							if ((!func.isThunk() &&
								CreateThunkFunctionCmd.isThunk(program, func))) {
								CreateFunctionCmd createFunctionCmd = new CreateFunctionCmd(null,
									func.getEntryPoint(), null, SourceType.ANALYSIS, false, true);
								if (createFunctionCmd.applyTo(program)) {
									AutoAnalysisManager amgr =
										AutoAnalysisManager.getAnalysisManager(program);
									amgr.functionDefined(
										new AddressSet(func.getEntryPoint(), func.getEntryPoint()));
									checkedTargets.delete(target, target); // take off set, so can check again
								}
							}
						}
					}
					continue;
				}

				// check for already looked at targets here, so if more pointers
				//    to a location are found (say jumps/calls to a location other than a data read/write
				//    The location will be checks
				if (checkedTargets.contains(target)) {
					continue;
				}
				checkedTargets.add(target);

				// if memory doesn't contain the target address
				if (!reference.isMemoryReference()) {
					continue;
				}
				if (!memory.contains(target)) {
					continue;
				}
				if (ignoreNewPointers.contains(target)) {
					continue;
				}

				// check if something is defined there
				// if it is a string, let is go through.
				boolean stuffDefined = false;
				boolean isUndefinedStuff = false;
				Data data = listing.getDefinedDataContaining(target);
				if (data != null) {
					DataType dt = data.getDataType();
					stuffDefined = true;
					if (!(dt instanceof StringDataType || data.isPointer())) {
						if (dt instanceof Undefined) {
							isUndefinedStuff = true;
						}
						else {
							continue;
						}
					}
				}
				else {
					Instruction targetInstr = listing.getInstructionContaining(target);
					if (targetInstr != null) {
						doneSubTest.addRange(targetInstr.getMinAddress(),
							targetInstr.getMaxAddress());
						// if this is a computed instruction, keep analyzing it
						if (cu instanceof Instruction) {
							if (!((Instruction) cu).getFlowType().isComputed()) {
								if (shouldBeValidFunction(program, targetInstr)) {
									// it is already disassembled, but not a function yet.
									disTargets.addRange(target, target);
								}
								continue;
							}
						}
						else {
							if (shouldBeValidFunction(program, targetInstr)) {
								// it is already disassembled, but not a function yet.
								disTargets.addRange(target, target);
							}
							continue;
						}
					}
				}

				// check if it could be code
//				if (memRefs[m].isUserDefined()) {
				Instruction instr = null;
				if (cu instanceof Instruction) {
					instr = (Instruction) cu;
				}

				if (instr != null) {
					AddressTable table = getAddressTable(program, instr,
						reference.getOperandIndex(), target, monitor);
					if (table != null) {
						if (table.getNumberAddressEntries() >= minimumAddressTableSize) {
							createFlowTable(program, instr, reference.getOperandIndex(), table,
								monitor);
							// if new code found, must yield analysis elsewhere
							if (newCodeFound) {
								leftSet = new AddressSet(set);
								leftSet.deleteRange(leftSet.getMinAddress(), addr);
								leftSet.addRange(addr, addr);
								break;
							}
							continue;
						}
					}
				}

				// TODO: decide whether we should look for code that is a potential address table.
				//
				if (subroutinesEnabled && /** !potentialAddressTable && **/
					!isUndefinedStuff && !doneSubTest.contains(target)) {
					RefType refType = reference.getReferenceType();
					// only check references that aren't marked as read/write
					if (!(refType.isRead() || refType.isWrite() ||
						hasDataAccessReferences(program, target))) {
						// assume someone else will handle this correctly.  We clearly can't here
						if (instr != null &&
							(instr.getFlowType().isJump() || instr.getFlowType().isCall())) {
							continue;
						}

						// if not an instruction, and value not used for a calculation
						if (instr == null || !isUsedForCalculation(instr, target)) {
							Address fromAddress = reference.getFromAddress();
							// only check in code marked executable if there is any
							if (executeSet == null || executeSet.contains(target) ||
								isFunctionPointer(listing, fromAddress)) {
								doneSubTest.addRange(target, target);
								Symbol sym = program.getSymbolTable().getSymbol(reference);

								// only allow code to fall into other code when subroutine on a data item
								if (pdis.isValidSubroutine(target, instr == null)) {
									// if this came from code, mark it as found code
									if (instr != null) {
										foundCodeBookmarkLocations.addRange(target, target);
									}
									// THIS IS a HACK.  Don't check address table locations.
									//   something else already is doing this.  Too much bad code is being found

									if (sym == null || !sym.getName().startsWith("AddrTable")) {
										disTargets.addRange(target, target);
									}
								}
							}
						}
					}
					else {
//							Err.debug(this, "is read/write at " + memRefs[m].getFromAddress());
					}
				}
//				}
				if (stuffDefined && !isUndefinedStuff) {
					continue;
				}

				if (asciiEnabled && checkForAscii(program, pdis, target)) {
					continue;
				}

				if (unicodeEnabled && checkForUnicode(program, pdis, target)) {
					continue;
				}

				// TODO: Maybe this should check for valid pointers, even if it was identified good code.
				if (pointerEnabled && !disTargets.contains(target) &&
					checkForPointer(program, pdis, target, true)) {
					data = program.getListing().getDefinedDataAt(target);
					if (data != null && data.isPointer()) {
						Address ptrAddr = data.getAddress(0);
						ignoreNewPointers.addRange(ptrAddr, ptrAddr);
					}
					continue;
				}
			}
		}

		// don't create functions where there is data
		AddressIterator aiter = disTargets.getAddresses(true);
		AddressSet throwOutSet = new AddressSet();
		AddressSet doneDisSet = new AddressSet();
		while (aiter.hasNext()) {
			Address addr = aiter.next();
			Data data = program.getListing().getDataContaining(addr);
			if (data != null) {
				if (data.isDefined()) {
					throwOutSet.add(addr);
				}
				continue;
			}
			Instruction instr = program.getListing().getInstructionContaining(addr);
			if (instr != null) {
				doneDisSet.add(addr);
			}
		}
		disTargets = disTargets.subtract(throwOutSet);

		if (!disTargets.isEmpty()) {
			// TODO: delayed disassembly should check if the code starts are still valid
			AddressSet doDisTargets = disTargets.subtract(doneDisSet);
			if (!doDisTargets.isEmpty()) {
				BackgroundCommand cmd = createDisassemblyCommandsForAddress(program, doDisTargets);
				mgr.schedule(cmd, AnalysisPriority.REFERENCE_ANALYSIS.after().after().priority());
			}

			createFunctions(program, disTargets);
			foundCodeBookmarkLocations = foundCodeBookmarkLocations.subtract(throwOutSet);
			AddressIterator foundIter = foundCodeBookmarkLocations.getAddresses(true);
			while (foundIter.hasNext()) {
				Address target = foundIter.next();
				program.getBookmarkManager()
						.setBookmark(target, BookmarkType.ANALYSIS,
							"Found Code", "Found code from operand reference");
			}
		}

		// Set up a one time analysis to get us back into here if
		//   there are still addresses on the set
		//
		if (newCodeFound && !leftSet.isEmpty()) {
			mgr.scheduleOneTimeAnalysis(this, leftSet);
		}
		return true;
	}

	private CompoundBackgroundCommand createDisassemblyCommandsForAddress(Program program,
			AddressSet locations) {
		CompoundBackgroundCommand backCmd =
			new CompoundBackgroundCommand("Subroutine References", false, true);

		Listing listing = program.getListing();
		int align = program.getLanguage().getInstructionAlignment();

		AddressIterator iter = locations.getAddresses(true);
		for (Address addr : iter) {
			// check the normalized address where disassembly will actually occur
			Address targetAddr = PseudoDisassembler.getNormalizedDisassemblyAddress(program, addr);
			if ((targetAddr.getOffset() % align) != 0) {
				continue; // not aligned
			}

			if (listing.getUndefinedDataAt(targetAddr) == null) {
				continue;
			}

			// need to create a context for each one.  Also disassembleCmd will align the address to disassemble
			DisassembleCommand disassembleCmd = new DisassembleCommand(addr, null, true);
			RegisterValue rval =
				PseudoDisassembler.getTargetContextRegisterValueForDisassembly(program, addr);
			disassembleCmd.setInitialContext(rval);
			backCmd.add(disassembleCmd);
		}

		return backCmd;
	}

	private boolean hasDataAccessReferences(Program program, Address target) {
		ReferenceIterator referencesTo = program.getReferenceManager().getReferencesTo(target);

		while (referencesTo.hasNext()) {
			Reference reference = referencesTo.next();

			RefType referenceType = reference.getReferenceType();

			if (referenceType.isRead() || referenceType.isWrite()) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check for any jumps to Externals (manufactured labels).
	 * Any externals directly jumped to should be looked at as a call.
	 *
	 * Note: this shouldn't affect jumps in thunks, but beware...
	 * @param monitor
	 * @throws CancelledException
	 */
	private boolean checkForExternalJump(Program program, Reference reference, TaskMonitor monitor)
			throws CancelledException {
		// Check any direct jumps into the EXTERNAL memory section
		//   These don't return!
		if (externalBlock == null) {
			return false;
		}

		Address toAddr = reference.getToAddress();
		if (!externalBlock.contains(toAddr)) {
			return false;
		}
		Address fromAddr = reference.getFromAddress();
		Instruction instr = program.getListing().getInstructionAt(fromAddr);

		// override flow
		if (instr != null && instr.getFlowType().isJump()) {
			instr.setFlowOverride(FlowOverride.CALL_RETURN);
			// Get rid of any bad disassembly bookmark
			AddressSet set = new AddressSet(toAddr);
			program.getBookmarkManager()
					.removeBookmarks(set, BookmarkType.ERROR,
						Disassembler.ERROR_BOOKMARK_CATEGORY, monitor);
		}

		// make sure function created at destination
		Function func = program.getFunctionManager().getFunctionAt(toAddr);
		if (func == null) {
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(null, toAddr,
				new AddressSet(toAddr, toAddr), SourceType.ANALYSIS);
			createFuncCmd.applyTo(program);
		}
		return true;
	}

	protected void createFunctions(Program program, AddressSet functionStarts) {
//		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

		// don't ever create functions from pointed to code, get at function starts another way
		// TODO: we could get corroborating information from other means
		//          (function right above, starts like a function, etc...)
		//
//		mgr.createFunction(functionStarts, false, AnalysisPriority.DATA_TYPE_PROPOGATION.getNext());
	}

	private boolean shouldBeValidFunction(Program program, Instruction targetInstr) {
		Function func =
			program.getFunctionManager().getFunctionContaining(targetInstr.getMinAddress());
		if (func != null) {
			return false;
		}
		ReferenceIterator refs =
			program.getReferenceManager().getReferencesTo(targetInstr.getMinAddress());
		while (refs.hasNext()) {
			Reference ref = refs.next();
			RefType refType = ref.getReferenceType();
			if (refType.isFlow()) {
				return false;
			}
			if (refType.isRead() || refType.isWrite()) {
				return false;
			}
		}
		return true;
	}

	private boolean isUsedForCalculation(Instruction instr, Address targetValue) {
		PcodeOp[] pcode = instr.getPcode();
		Varnode target = null;
		for (PcodeOp element : pcode) {
			int op = element.getOpcode();
			switch (op) {
				case PcodeOp.LOAD:
				case PcodeOp.STORE:
					// is the target varnode the target out/in location
					if (element.getInput(1).equals(target)) {
						return true;
					}
			}
			// is the value of the target varnode one of the inputs
			//     then the target becomes the output varnode
			Varnode[] inputs = element.getInputs();
			for (Varnode input : inputs) {
				if ((target != null && target.equals(input)) || (input.isConstant() &&
					input.getOffset() == targetValue.getUnsignedOffset())) {
					if (op == PcodeOp.LOAD || op == PcodeOp.STORE) {
						continue;
					}
					if (op != PcodeOp.COPY) {
						return true;
					}
					Varnode pt = element.getOutput();
					if (pt != null) {
						target = pt;
					}
				}
			}
		}
		return false;
	}

	private boolean isFunctionPointer(Listing listing, Address fromAddress) {
		Data fromData = listing.getDataContaining(fromAddress);
		if (fromData != null) {
			int offset = (int) fromAddress.subtract(fromData.getAddress());
			Data primitiveAt = fromData.getPrimitiveAt(offset);
			DataType dataType3 = primitiveAt.getDataType();
			if (dataType3 instanceof Pointer) {
				Pointer pointer = (Pointer) dataType3;
				DataType pointerDataType = pointer.getDataType();
				if (pointerDataType instanceof FunctionDefinition) {
					return true;
				}
			}
		}
		return false;
	}

	private AddressSet getExecuteSet(Memory memory) {
		AddressSet set = new AddressSet();
		MemoryBlock blocks[] = memory.getBlocks();
		for (MemoryBlock block : blocks) {
			if (block.isExecute()) {
				set.addRange(block.getStart(), block.getEnd());
			}
		}
		return (set.isEmpty() ? null : set);
	}

	private AddressTable getAddressTable(Program program, Instruction instr, int opIndex,
			Address target, TaskMonitor monitor) {
		FlowType ftype = instr.getFlowType();

		// if this is a computed jump or call, with just 1 address operand, it can't be a jump/call table
		if (((ftype.isJump() || ftype.isCall()) && ftype.isComputed())) {
			if (instr.getNumOperands() == 1 && instr.getAddress(0) != null) {
				return null;
			}
		}
		AddressTable table =
			AddressTable.getEntry(program, target, monitor, true, MINIMUM_POTENTIAL_TABLE_SIZE,
				switchTableAlignment, 0, AddressTable.MINIMUM_SAFE_ADDRESS, relocationGuideEnabled);
		if (table != null) {
			Reference[] refs = instr.getOperandReferences(opIndex);
			for (Reference ref : refs) {
				if (ref.isOffsetReference()) {
					OffsetReference oref = (OffsetReference) ref;
					if (oref.getOffset() < -4) {
						table.setNegativeTable(true);
					}
				}
			}
			return table;
		}

		if (!switchTableEnabled || !((ftype.isJump() || ftype.isCall()) && ftype.isComputed())) {
			return null;
		}

		Object opObjects[] = instr.getOpObjects(opIndex);
		// figure out the multiple away
		long entryLen = 0;
		for (Object opObject : opObjects) {
			if (opObject instanceof Scalar) {
				Scalar sc = (Scalar) opObject;
				long value = sc.getUnsignedValue();
				if (value == 4 || value == 2 || value == 8) {
					entryLen = value;
					break;
				}
			}
		}
		if (entryLen == 0) {
			return null;
		}

//		 look for a negative offset table
		AddressTable lastGoodTable = null;
		Address negAddr = null;
		int i;
		for (i = 0; i < MAX_NEG_ENTRIES; i++) {
			try {
				negAddr = target.subtractNoWrap((i + 3) * entryLen);
			}
			catch (AddressOverflowException e) {
				break;
			}

			// if there is an instruction at the offset
			if (program.getListing().getInstructionContaining(negAddr) != null) {
				break;
			}

			AddressTable negTable = AddressTable.getEntry(program, negAddr, monitor, false, 3,
				switchTableAlignment, 0, AddressTable.MINIMUM_SAFE_ADDRESS, relocationGuideEnabled);
			if (negTable == null) {
				break;
			}
			lastGoodTable = negTable;
			negTable.setNegativeTable(true);
		}
		if (i == MAX_NEG_ENTRIES) {
			return null;
		}

		if (lastGoodTable != null) {
			instr.removeOperandReference(opIndex, target);
			program.getReferenceManager()
					.addOffsetMemReference(instr.getMinAddress(),
						lastGoodTable.getTopAddress(), -((i + 3) * entryLen), RefType.DATA,
						SourceType.ANALYSIS, opIndex);
		}

		return lastGoodTable;
	}

	private void createFlowTable(Program program, Instruction instr, int opindex,
			AddressTable table, TaskMonitor monitor) {
		FlowType ftype = instr.getFlowType();

		if (ftype.isJump() || ftype.isCall()) {
			if (!switchTableEnabled) {
				return;
			}
			newCodeFound |= table.createSwitchTable(program, instr, opindex, true, monitor);
		}

		if (!addressTablesEnabled) {
			return;
		}

		if (clearAllUndefined(program, table.getTopAddress(), table.getByteLength())) {
			table.makeTable(program, 0, table.getNumberAddressEntries(), false);
		}

//		if (ftype.isCall()) {
//			table.disassemble(program);
//			if (ftype.isComputed()) {
//				Address tablesEntries[] = table.getTableElements();
//				for (int i = 0; i < tablesEntries.length; i++) {
//					instr.addOperandReference(opindex, tablesEntries[i], ftype);
//				}
//			}
//			return;
//		}
	}

	/**
	 * Check if the target reference is to a ascii string
	 *
	 * @param program program to check in
	 * @param pdis disassembler to use
	 * @param target target data location
	 * @return true if an ascii string was created.
	 */
	private boolean checkForAscii(Program program, PseudoDisassembler pdis, Address target) {
		// check if it could be a good ANSII string
		int asciiLen = checkAnsiString(program.getMemory(), target);
		if (asciiLen > 0) {
			if (desiredDataMemoryContainsReference(program, target, asciiLen)) {
				if (asciiLen > 4) {
					return true; // didn't create a string, but act like we did!
				}
				return false;
			}
			// check if it could be code
			if (!isValidInstruction(pdis, target)) {
				if (clearAllUndefined(program, target, asciiLen)) {
					Command cmd = new CreateStringCmd(target, asciiLen, false);
					cmd.applyTo(program);
				}
			}
			return true;
		}
		return false;
	}

	/**
	 * Check if the target reference is to a unicode string
	 *
	 * @param program program to check in
	 * @param pdis disassembler to use
	 * @param target target data location
	 * @return true if a unicode string was created.
	 */
	private boolean checkForUnicode(Program program, PseudoDisassembler pdis, Address target) {
		// check if it could be a good unicode string
		int uniLen = checkUnicodeString(program.getMemory(), target);
		if (uniLen > 0) {
			if (desiredDataMemoryContainsReference(program, target, uniLen)) {
				return false;
			}
			// check if it could be code
			if (!isValidInstruction(pdis, target)) {
				if (clearAllUndefined(program, target, uniLen)) {
					Command cmd = new CreateStringCmd(target, 2 * (uniLen + 1), true);
					cmd.applyTo(program);
				}
			}
			return true;
		}
		return false;
	}

	/**
	* Check if the set of bytes that should be used is all undefined, or all undefined data types.
	*   It means that whatever laid things down here only knew that something was accessed of some size.
	*
	* @param lenBytes
	*
	* @return false if data couldn't be cleared away
	*/
	private boolean clearAllUndefined(Program program, Address start, int lenBytes) {
		if (lenBytes < 1) {
			return false;
		}

		AddressSet set = new AddressSet(start, start.add(lenBytes - 1));

		if (program.getListing().isUndefined(set.getMinAddress(), set.getMaxAddress())) {
			return true;
		}

		CodeUnitIterator iter = program.getListing().getCodeUnits(set, true);

		// check that all real code units are undefined
		while (iter.hasNext()) {
			CodeUnit codeUnit = iter.next();
			// found something not data, return
			if (!(codeUnit instanceof Data)) {
				return false;
			}
			Data data = (Data) codeUnit;
			DataType dt = data.getDataType();
			// not undefined data
			if (!(Undefined.isUndefined(dt))) {
				return false;
			}
		}
		program.getListing().clearCodeUnits(set.getMinAddress(), set.getMaxAddress(), false);
		return true;
	}

	private boolean desiredDataMemoryContainsReference(Program program, Address rangeStartAddress,
			int rangeLength) {

		Address nextAddress;
		try {
			nextAddress = rangeStartAddress.add(1);
		}
		catch (AddressOutOfBoundsException e) {
			// target is at the end of the space
			return false;
		}

		AddressIterator iterator =
			program.getReferenceManager().getReferenceDestinationIterator(nextAddress, true);
		Address referenceAddress = iterator.next();
		if (referenceAddress == null) {
			return false;
		}

		AddressSpace targetSpace = rangeStartAddress.getAddressSpace();
		AddressSpace nextSpace = referenceAddress.getAddressSpace();
		if (!targetSpace.equals(nextSpace)) {
			return false;
		}

		long distance = referenceAddress.subtract(rangeStartAddress);
		return distance < rangeLength;
	}

	private boolean checkForPointer(Program program, PseudoDisassembler pdis, Address target,
			boolean doit) {
		try {

			if (relocationGuideEnabled && !isValidRelocationAddress(program, target)) {
				return false;
			}

			// get the value in address form of the bytes at address a
			Memory memory = program.getMemory();
			Address testAddr =
				PointerDataType.getAddressValue(new DumbMemBufferImpl(memory, target),
					program.getDefaultPointerSize(), target.getAddressSpace());

			// test that the value isn't 0
			//    May be bad if an address table has a 0 in it, but normally
			//    0 is not found in memory anyway, so better to be conservative
			// not good if pointer is a small number
			//   don't chance it
			if (testAddr == null || (testAddr.getOffset() >= 0 && testAddr.getOffset() < 4096L)) {
				return false;
			}

			// if the address isn't valid for this processors alignment
			if (testAddr.getOffset() % switchTableAlignment != 0) {
				return false;
			}

			// See if the tested address is contained in memory
			if (!memory.contains(testAddr)) {
				Symbol syms[] = program.getSymbolTable().getSymbols(testAddr);
				if (syms == null || syms.length == 0 || syms[0].getSource() == SourceType.DEFAULT) {
					return false;
				}
			}

			if (desiredDataMemoryContainsReference(program, target, target.getPointerSize())) {
				return false;
			}

			// make sure not offcut
			CodeUnit cu = program.getListing().getCodeUnitContaining(testAddr);
			if (cu != null && !cu.getMinAddress().equals(testAddr)) {
				return false;
			}

			// make sure it isn't into the middle of code
			//   If there is an instruction before this one, it should not fall into it.
			if (cu instanceof Instruction) {
				Instruction instr = (Instruction) cu;
				if (instr.isInDelaySlot()) {
					return false;
				}
				Address fallFrom = instr.getFallFrom();
				if (fallFrom != null) {
					// only consider if function already exists at this instr
					if (program.getFunctionManager().getFunctionAt(instr.getMinAddress()) == null) {
						return false;
					}
				}
				else {
					// don't reference inside the middle of a function
					Function func = program.getFunctionManager().getFunctionContaining(testAddr);
					if (func != null && !func.getEntryPoint().equals(testAddr)) {
						return false;
					}
				}
			}

			// TODO:  Even if this smells like a pointer, we should put it into a constant POOL
			//        for later analysis.
			if (doit && clearAllUndefined(program, target, program.getDefaultPointerSize())) {
				DataType adt =
					program.getDataTypeManager().addDataType(new PointerDataType(), null);
				Command cmd = new CreateDataCmd(target, adt);
				cmd.applyTo(program);
			}
			return true;
		}
		catch (AddressOutOfBoundsException e) {
			return false;
		}
	}

	/**
	 * Check if the address is in the Relocation table.
	 * This only counts for relocatable programs.  Every address should be in the relocation table.
	 * @param target location to check
	 * @return
	 */
	private boolean isValidRelocationAddress(Program program, Address target) {
		// If the program is relocatable, and this address is not one of the relocations
		//   can't be a pointer
		RelocationTable relocationTable = program.getRelocationTable();
		if (relocationTable.isRelocatable()) {
			// if it is relocatable, then there should be no pointers in memory, other than relacatable ones
			if (relocationTable.getSize() > 0 && relocationTable.getRelocation(target) == null) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Check if there is a valid instruction at the target address
	 *
	 * @param pdis - pseudo disassembler
	 * @param target - taraget address to disassemble
	 * @return
	 */
	private boolean isValidInstruction(PseudoDisassembler pdis, Address target) {
//		try {
//			// look 8 instructions worth of fallthroughs to see if this
//			//   is a valid run of instructions.
//			for (int i=0; i < 10; i++) {
//				Instruction instr;
//				instr = pdis.disassemble(target);
//				if (instr == null) {
//					return false;
//				}
//				if (!instr.hasFallthrough()) {
//					return true;
//				}
//				target = instr.getFallThrough();
//			}
//		} catch (InsufficientBytesException e) {
//		} catch (UnknownInstructionException e) {
//		} catch (UnknownContextException e) {
//		}
		return false;
	}

	/* OUTPUT VERTEX INFO ROUTINES */

	/** checkAnsiString:
	 * Checks ascii string for "goodness".
	 *
	 */
	private int checkAnsiString(Memory mem, Address adref) {
		int len = getStringLength(mem, adref, processorAlignment); // returns -1 for bad

		if (len <= 0) {
			return 0;
		}

//		int len2 = getStrLen(mem, adref.subtract(4));
//		if (len2 > len + 2)
//			return 0;

		return len;
	}

	/**
	 * Returns the length of the Unicode string found at address.
	 *
	 * @return length of string in in words (two byte unicode characters).
	 */
	private int checkUnicodeString(Memory mem, Address adref) {
		int len = getWStrLen(mem, adref); // returns -1 for bad

		if (len <= 0) {
			return 0;
		}

		int len2 = getWStrLen(mem, adref.subtractWrap(8));
		if (len2 > len + 2) {
			return 0;
		}

		if (len > 3) {
			return len;
		}

		return 0;
	}

	/**
	 * getStringLength determines the length of the null terminated ASCII
	 * string beginning at the indicated address in memory.
	 * The length of the string includes the null terminator character
	 * and any additional bytes to make it the correct alignment length for
	 * this processor.
	 * This method returns -1 if it encounters invalid characters before
	 * reaching the null terminator.
	 * It also returns -1 if the number of characters before the null is less
	 * than the current minimum string length obtained from the analysis options.
	 * @param memory the program memory for obtaining the strings bytes
	 * @param startAddress = address where string is believed to begin
	 * @param stringAlignment the alignment size for the string
	 * @return length of proposed string, -1 if not string.
	 * Note: The length of the string includes the null terminator character
	 * and any additional bytes to make it the correct alignment length for
	 * this processor.
	 *
	 * For analyzing null-terminated strings.  If a non-printable
	 * character occurs before a null byte, it is not a string and
	 * -1 is returned.  Also if 1000 chars have gone by without
	 * a null, then again -1 is returned.
	 */
	int getStringLength(Memory memory, Address startAddress, int stringAlignment) {

		try {
			byte[] bytes = new byte[1000];
			int numBytes = memory.getBytes(startAddress, bytes);
			int nullOffset = getNullTerminatorOffset(bytes, numBytes);
			if ((nullOffset < 0) || (nullOffset < minStringLength)) {
				return -1;
			}
			int length = nullOffset + 1;
			if (alignStringsEnabled) {
				/* TODO This currently uses the processor alignment to make
				 * sure the length returned is a multiple of the alignment value.
				 * Is this the correct thing or should the alignment padding cause
				 * the address of the next byte following the padded string to be
				 * aligned at a multiple of the alignment?
				 */
				int modAlignment = length % stringAlignment;
				if (modAlignment != 0) {
					int numAlignBytes = stringAlignment - modAlignment;
					// TODO Should this validate the alignment bytes? It doesn't currently.
					length += numAlignBytes;
					// If we don't have enough bytes to align it then return "bad" indicator.
					if (length > numBytes) {
						return -1;
					}
				}
			}
			return length;
		}
		catch (MemoryAccessException e) {
			return -1;
		}
	}

	private int getNullTerminatorOffset(byte[] bytes, int numBytes) {
		for (int i = 0; i < numBytes; i++) {
			if (bytes[i] == 0) {
				return i; // Found the null terminator.
			}
			if (!isValidAsciiByte(bytes[i])) {
				return -1;
			}
		}
		return -1;
	}

	private boolean isValidAsciiByte(byte b) {
		final byte TAB = 0x09;
		final byte CARRIAGE_RETURN = 0x0a;
		final byte LINE_FEED = 0x0d;
		// If we hit an invalid character before the null then not good string.
		// However, we should allow tab, carriage return, and line feed.
		if (b >= 0x7f) {
			return false;
		}
		if ((b < 0x20) && b != TAB && b != CARRIAGE_RETURN && b != LINE_FEED) {
			return false;
		}
		return true;
	}

	/**
	 * getWStrLen
	 * @param ad = address where unicode string is supposed to begin
	 * @return number of unicode chars in string, -1 if not
	 * a unicode string.  NOTE: Only English strings are considered.
	 *
	 */
	int getWStrLen(Memory memory, Address ad) {
		try {
			for (int i = 0; i < 1000; i++) {
				// if the address is negative (on the stack), you can
				// end up adding like 0xa to 0xfffffff6 and overflow, so I
				// turned this into a wrapped add
				short value = memory.getShort(ad.addWrap(2 * i));
				if (value == 0) {
					return i;
				}
				// allow tab, carriage return, and linefeed
				if (value != 0x09 && value != 0x0a && value != 0x0d &&
					(value < 0x20 || value >= 0x7f)) {
					return -1;
				}
			}
		}
		catch (MemoryAccessException e) {
			return -1;
		}
		return -1;
	}

	@Override
	public void registerOptions(Options options, Program program) {
		HelpLocation helpLocation = new HelpLocation("AutoAnalysisPlugin",
			"Auto_Analysis_Option_Instructions");

		if (minimumAddressTableSize == -1) {
			calculateMinimumAddressTableSize(program);
		}
		options.registerOption(OPTION_NAME_ASCII, asciiEnabled, helpLocation,
			OPTION_DESCRIPTION_ASCII);
		options.registerOption(OPTION_NAME_UNICODE, unicodeEnabled, helpLocation,
			OPTION_DESCRIPTION_UNICODE);
		options.registerOption(OPTION_NAME_ALIGN_STRINGS, alignStringsEnabled, helpLocation,
			OPTION_DESCRIPTION_ALIGN_STRINGS);
		options.registerOption(OPTION_NAME_MIN_STRING_LENGTH, minStringLength, helpLocation,
			OPTION_DESCRIPTION_MIN_STRING_LENGTH);
		options.registerOption(OPTION_NAME_POINTER, pointerEnabled, helpLocation,
			OPTION_DESCRIPTION_POINTER);
		options.registerOption(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled, helpLocation,
			OPTION_DESCRIPTION_RELOCATION_GUIDE);
		options.registerOption(OPTION_NAME_SUBROUTINE, subroutinesEnabled, helpLocation,
			OPTION_DESCRIPTION_SUBROUTINE);
		options.registerOption(OPTION_NAME_ADDRESS_TABLE, addressTablesEnabled, helpLocation,
			OPTION_DESCRIPTION_ADDRESS_TABLE);
		options.registerOption(OPTION_NAME_SWITCH, switchTableEnabled, helpLocation,
			OPTION_DESCRIPTION_SWITCH);
		options.registerOption(OPTION_NAME_SWITCH_ALIGNMENT, switchTableAlignment, helpLocation,
			OPTION_DESCRIPTION_SWITCH_ALIGNMENT);
		options.registerOption(OPTION_NAME_MINIMUM_TABLE_SIZE, minimumAddressTableSize,
			helpLocation, OPTION_DESCRIPTION_MINIMUM_TABLE_SIZE);
		options.registerOption(OPTION_NAME_RESPECT_EXECUTE_FLAG, respectExecuteFlags, helpLocation,
			OPTION_DESCRIPTION_RESPECT_EXECUTE_FLAG);

	}

	@Override
	public void optionsChanged(Options options, Program program) {

		minStringLength = options.getInt(OPTION_NAME_MIN_STRING_LENGTH, minStringLength);
		switchTableAlignment = options.getInt(OPTION_NAME_SWITCH_ALIGNMENT, switchTableAlignment);
		minimumAddressTableSize =
			options.getInt(OPTION_NAME_MINIMUM_TABLE_SIZE, minimumAddressTableSize);

		asciiEnabled = options.getBoolean(OPTION_NAME_ASCII, asciiEnabled);
		unicodeEnabled = options.getBoolean(OPTION_NAME_UNICODE, unicodeEnabled);
		alignStringsEnabled = options.getBoolean(OPTION_NAME_ALIGN_STRINGS, alignStringsEnabled);
		pointerEnabled = options.getBoolean(OPTION_NAME_POINTER, pointerEnabled);
		relocationGuideEnabled =
			options.getBoolean(OPTION_NAME_RELOCATION_GUIDE, relocationGuideEnabled);
		subroutinesEnabled = options.getBoolean(OPTION_NAME_SUBROUTINE, subroutinesEnabled);
		addressTablesEnabled = options.getBoolean(OPTION_NAME_ADDRESS_TABLE, addressTablesEnabled);
		switchTableEnabled = options.getBoolean(OPTION_NAME_SWITCH, switchTableEnabled);
		respectExecuteFlags =
			options.getBoolean(OPTION_NAME_RESPECT_EXECUTE_FLAG, respectExecuteFlags);
	}

}
