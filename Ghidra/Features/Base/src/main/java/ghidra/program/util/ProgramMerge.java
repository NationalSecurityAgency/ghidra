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

import java.util.*;

import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.database.properties.UnsupportedMapDB;
import ghidra.program.disassemble.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.*;
import ghidra.util.*;
import ghidra.util.datastruct.LongLongHashtable;
import ghidra.util.exception.*;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramMerge</CODE> is a class for merging the differences between two
 * programs. The differences are merged from program2 into program1.
 * <P>Program1 is the program being modified by the merge. Program2 is source
 * for obtaining differences to apply to program1.
 * <P>If name conflicts occur while merging, the item (for example, symbol) will
 * be merged with a new name that consists of the original name followed by "_conflict"
 * and a one up number.
 */

public class ProgramMerge implements PropertyVisitor {

	/** Suffix that is attached to a symbol name and then followed by a number to create a new unique symbol name. */
	public static String SYMBOL_CONFLICT_SUFFIX = "_conflict";
	/** Indicates how often to show progress counter changes. */
	private static final int PROGRESS_COUNTER_GRANULARITY = 129;
	/** Message indicating errors that occurred during a merge. */
	private StringBuffer errorMsg;
	/** Message indicating non-error information about a merge. */
	private StringBuffer infoMsg;
	/** The address translator converts an address from the origin program to an equivalent address in the result program. */
	private AddressTranslator originToResultTranslator;
	/** The first program that will be modified by the merge. */
	private Program resultProgram;
	/** The second program (used as read only) for obtaining differences to merge. */
	private Program originProgram;
	/** The listing for the program being merged into. */
	private Listing resultListing;
	/** The listing for the program being merged from. */
	private Listing originListing;
	/** The current code unit that is being modified when a user defined property is merged. */
	private CodeUnit resultCu;
	/** The current property name being merged, when merging user defined properties. */
	private String propertyName;

	private SymbolMerge symbolMerge;
	private FunctionMerge functionMerge;
	private LongLongHashtable conflictSymbolIDMap; // newly created conflict symbol names (key = original program's symbol ID; value = result program's symbol ID)
	private HashMap<String, DupEquate> dupEquates; // duplicate equate names

	/**
	 * <CODE>ProgramMerge</CODE> allows the merging of differences from program2
	 * into program1 (the result program).
	 *
	 * @param resultProgram The result program that will get modified by merge.
	 * @param originProgram The program (used as read only) for obtaining
	 * differences to merge.
	 */
	public ProgramMerge(Program resultProgram, Program originProgram) {
		this.originToResultTranslator = new DefaultAddressTranslator(resultProgram, originProgram);
		init(resultProgram, originProgram);
	}

	/**
	 * <CODE>ProgramMerge</CODE> allows the merging of differences from program2 (the origin program)
	 * into program1 (the result program).
	 * <br>If the address translator is not a "one for one translator" then certain methods within
	 * this class will throw an UnsupportedOperationException.
	 * The destination program from the address translator should be the result program into
	 * which changes are made.
	 * The source program from the translator is the origin program for obtaining the changes.
	 *
	 * @param originToResultTranslator converts addresses from the origin program into an
	 * equivalent address in the destination program.
	 * @see AddressTranslator
	 */
	public ProgramMerge(AddressTranslator originToResultTranslator) {
		this.originToResultTranslator = originToResultTranslator;
		init(originToResultTranslator.getDestinationProgram(),
			originToResultTranslator.getSourceProgram());
	}

	/**
	 * Initializes numerous variables to be used by the ProgramMerge.
	 *
	 * @param result the result program where changes are written.
	 * @param origin the origin program to get information to apply to program1.
	 */
	private void init(Program result, Program origin) {
		this.resultProgram = result;
		this.originProgram = origin;
		if (resultProgram == null || originProgram == null) {
			throw new IllegalArgumentException("program cannot be null.");
		}
		this.resultListing = this.resultProgram.getListing();
		this.originListing = this.originProgram.getListing();
		errorMsg = new StringBuffer();
		infoMsg = new StringBuffer();
		conflictSymbolIDMap = new LongLongHashtable();
		dupEquates = new HashMap<>();
		symbolMerge = new SymbolMerge(originToResultTranslator);
		functionMerge = new FunctionMerge(originToResultTranslator);
	}

	/** Gets the result program. Merge changes are applied to this program.
	 * @return the program being changed by the merge.
	 */
	public Program getResultProgram() {
		return resultProgram;
	}

	/** Gets the origin program. This program is used for obtaining things to merge into program1.
	 * @return the program we are obtaining the changes from which we will merge.
	 */
	public Program getOriginProgram() {
		return originProgram;
	}

	/**
	 * Clears all error messages and information messages.
	 */
	void clearMessages() {
		if (infoMsg.length() > 0) {
			infoMsg = new StringBuffer();
		}
		if (errorMsg.length() > 0) {
			errorMsg = new StringBuffer();
		}
	}

	/**
	 * Determines if this ProgramMerge currently has an error message.
	 * @return true if there is an error message.
	 */
	public boolean hasErrorMessage() {
		return (errorMsg.length() > 0);
	}

	/**
	 * Determines if this ProgramMerge currently has an informational message.
	 * @return true if there is an information message.
	 */
	public boolean hasInfoMessage() {
		return (infoMsg.length() > 0);
	}

	/**
	 * Get the error messages that resulted from the last call to a merge or
	 * replace method. These are errors that prevented something from being merged.
	 * <br>Important: Call clearErrorMessage() to clear the current error message after this returns it.
	 * @return the error message string or an empty string if there were no problems with the merge.
	 */
	public String getErrorMessage() {
		return errorMsg.toString();
	}

	/**
	 * Get the information messages that resulted from the last call to a merge or
	 * replace method. These messages are non-critical changes that were
	 * necessary during the merge. For example giving a symbol a name with a conflict
	 * extension because another symbol with that name existed elsewhere in the
	 * program already.
	 * <br>Important: Call clearInfoMessage() to clear the current info message after this returns it.
	 * @return the information message string or an empty string if there were no informational
	 * messages for the merge.
	 */
	public String getInfoMessage() {
		return infoMsg.toString();
	}

	/**
	 * This method clears the current error message.
	 */
	public void clearErrorMessage() {
		errorMsg = new StringBuffer();
	}

	/**
	 * This method clears the current informational message.
	 */
	public void clearInfoMessage() {
		infoMsg = new StringBuffer();
	}

	// **** PROGRAM CONTEXT REGISTERS methods ****

	/**
	 * <CODE>mergeProgramContext</CODE> merges the program context (register values)
	 * into the result program.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set are derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	void mergeProgramContext(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge program context.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Applying Program Context...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		ProgramContext resultContext = resultProgram.getProgramContext();
		ProgramContext originContext = originProgram.getProgramContext();
		ArrayList<Register> originRegs = new ArrayList<>(originContext.getRegisters());
		// Sort the registers by size so that largest come first.
		// This prevents the remove call below from incorrectly clearing
		// smaller registers that are part of a larger register.
		Collections.sort(originRegs, (r1, r2) -> r2.getBitLength() - r1.getBitLength());
		AddressRangeIterator originRangeIter = originAddressSet.getAddressRanges();
		while (originRangeIter.hasNext() && !monitor.isCancelled()) {
			AddressRange originRange = originRangeIter.next();
			AddressRange resultRange = originToResultTranslator.getAddressRange(originRange);
			monitor.setMessage(
				"Applying Program Context: " + originRange.getMinAddress().toString(true));
			for (Register originReg : originRegs) {
				if (!originReg.isBaseRegister() || originReg.isProcessorContext()) {
					continue;
				}
				monitor.checkCanceled();
				try {
					mergeProgramContext(resultContext, originContext, originReg, originRange,
						resultRange, monitor);
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}
	}

	/**
	 * Merge context register values over a specified address range.  It is very important that all
	 * instructions be cleared over this range in the result program prior to invoking this
	 * method.
	 * @param resultContext
	 * @param originContext
	 * @param originReg
	 * @param originRange
	 * @param resultRange
	 * @param monitor
	 * @throws CancelledException
	 * @throws ContextChangeException if an instruction was encountered where a context register
	 * value change was attempted
	 */
	private void mergeProgramContext(ProgramContext resultContext, ProgramContext originContext,
			Register originReg, AddressRange originRange, AddressRange resultRange,
			TaskMonitor monitor) throws CancelledException, ContextChangeException {
		Register resultReg = resultContext.getRegister(originReg.getName());
		if (resultReg == null) {
			return;
		}
		AddressRangeIterator origValueIter = originContext.getRegisterValueAddressRanges(originReg,
			originRange.getMinAddress(), originRange.getMaxAddress());
		resultContext.remove(resultRange.getMinAddress(), resultRange.getMaxAddress(), resultReg);
		while (origValueIter.hasNext()) {
			monitor.checkCanceled();
			AddressRange origValueRange = origValueIter.next();
			AddressRange resultValueRange =
				originToResultTranslator.getAddressRange(origValueRange);
			RegisterValue originValue =
				originContext.getRegisterValue(originReg, origValueRange.getMinAddress());
			if (originValue != null && originValue.hasAnyValue()) {
				RegisterValue resultValue = new RegisterValue(resultReg, originValue.toBytes());
				resultContext.setRegisterValue(resultValueRange.getMinAddress(),
					resultValueRange.getMaxAddress(), resultValue);
			}
		}
	}

	// **** BYTE methods ****

	/**
	 * Copies the bytes to the result program from the origin program for the specified set of
	 * address ranges.
	 * @param toProgram program that the bytes are copied to.
	 * @param fromProgram program the bytes are copied from.
	 * @param originAddressSet the set of address ranges to be copied.
	 * The addresses in this set are derived from the origin program.
	 *
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels copy bytes via the monitor.
	 */
	private void copyBytesInRanges(AddressSetView originAddressSet, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException {
		Memory toMem = resultProgram.getMemory();
		Memory fromMem = originProgram.getMemory();
		// Copy each range.
		AddressRangeIterator iter = originAddressSet.getAddressRanges();
		while (iter.hasNext()) {
			monitor.checkCanceled();
			AddressRange fromRange = iter.next();
			copyByteRange(toMem, fromMem, fromRange);
		}
	}

	/**
	 * Copies the bytes to one program memory from another for the specified
	 * address range.
	 * @param toMem program memory that the bytes are copied to.
	 * @param fromMem program memory the bytes are copied from.
	 * @param fromAddressRange the address range to be copied.
	 * The addresses in this range are derived from the program associated with the "to memory".
	 *
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	private void copyByteRange(Memory toMem, Memory fromMem, AddressRange fromAddressRange)
			throws MemoryAccessException {

		// Copy the bytes for this range
		int length = 0;
		Address fromWriteAddress = fromAddressRange.getMinAddress();
		for (long len = fromAddressRange.getLength(); len > 0; len -= length) {
			length = (int) Math.min(len, Integer.MAX_VALUE);
			byte[] bytes = new byte[length];
			fromMem.getBytes(fromWriteAddress, bytes);
			Address toWriteAddress = originToResultTranslator.getAddress(fromWriteAddress);
			toMem.setBytes(toWriteAddress, bytes);
			if (len > length) {
				fromWriteAddress = fromWriteAddress.add(length);
			}
		}
	}

	/** <CODE>mergeBytes</CODE> merges byte differences within the specified
	 *  address set.
	 * <br>Note: Any instructions at the equivalent byte addresses in the result program will get cleared and
	 * re-created resulting in the existing references being dropped.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set are derived from the origin program.
	 * @param overwriteInstructions if true affected instructions will be cleared and
	 * re-disassmebled after bytes are modified
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 *
	 * @throws MemoryAccessException if bytes can't be merged.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	public void mergeBytes(final AddressSetView originAddressSet, boolean overwriteInstructions,
			TaskMonitor monitor)
			throws MemoryAccessException, CancelledException, UnsupportedOperationException {
		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge bytes.";
			throw new UnsupportedOperationException(message);
		}
		AddressSet originByteSet =
			originAddressSet.subtract(ProgramMemoryUtil.getAddressSet(originProgram, false));
		if (originByteSet.isEmpty()) {
			return;
		}

		monitor.setMessage("Finding Instructions...   ");
		AddressSet resultByteSet =
			DiffUtility.getCompatibleAddressSet(originByteSet, resultProgram);
		AddressSet resultInstructionSet = getInstructionSet(resultByteSet, resultListing);

		// Clear the instructions.
		if (overwriteInstructions) {
			monitor.setMessage("Clearing Instructions...   ");
			AddressRangeIterator resultRangeIter = resultInstructionSet.getAddressRanges();
			int count = 0;
			while (resultRangeIter.hasNext()) {
				monitor.checkCanceled();
				AddressRange resultRange = resultRangeIter.next();
				Address resultMin = resultRange.getMinAddress();
				Address resultMax = resultRange.getMaxAddress();
				resultListing.clearCodeUnits(resultMin, resultMax, false, monitor);
				if (count == PROGRESS_COUNTER_GRANULARITY) {
					monitor.setMessage("Clearing Instructions...   " + resultMin.toString(true));
					count = 0;
				}
			}
		}
		else {
			// ignore instruction locations
			AddressSet originInstructionSet =
				DiffUtility.getCompatibleAddressSet(resultInstructionSet, originProgram);
			originByteSet = originByteSet.subtract(originInstructionSet);
			if (originByteSet.isEmpty()) {
				return;
			}
		}

		// Make sure we are only trying to copy bytes to where we have initialized addresses in the result.
		Memory memory = resultProgram.getMemory();
		AddressSetView initializedAddressSet = memory.getLoadedAndInitializedAddressSet();
		AddressSet originInitializedAddressSet =
			DiffUtility.getCompatibleAddressSet(initializedAddressSet, originProgram);
		originByteSet = originByteSet.intersect(originInitializedAddressSet);

		// Get the bytes for each of the address ranges.
		// Overwrite each range's bytes in the merge program.
		monitor.setMessage("Copying Bytes...   ");
		copyBytesInRanges(originByteSet, monitor);

		// Restore the instructions (if possible).
		if (overwriteInstructions) {
			Disassembler disassembler = Disassembler.getDisassembler(resultProgram, monitor,
				DisassemblerMessageListener.IGNORE);
			monitor.setMessage("Restoring Instructions...   ");
			AddressRangeIterator rangeIter = resultInstructionSet.getAddressRanges();
			int count = 0;
			while (rangeIter.hasNext()) {
				monitor.checkCanceled();
				AddressRange range = rangeIter.next();
				Address min = range.getMinAddress();
				Address max = range.getMaxAddress();
				disassembler.disassemble(min, new AddressSet(min, max), false);
				if (count == PROGRESS_COUNTER_GRANULARITY) {
					monitor.setMessage("Restoring Instructions...   " + min.toString(true));
					count = 0;
				}
			}
		}
	}

	/**
	 * Get the address set for all instructions that overlap the indicated byte address set.
	 * @param byteAddressSet the byte address set
	 * The addresses in this set should be derived from the same program for the listing passed as
	 * parameter 2.
	 * @param listing the listing to check for instructions
	 * @return the instruction address set. The addresses in this set will have an address
	 * factory matching that of the byteAddressSet.
	 */
	private AddressSet getInstructionSet(AddressSet byteAddressSet, Listing listing) {
		// Get the Instruction address set.
		AddressSet instructionSet = new AddressSet();
		AddressRangeIterator rangeIter = byteAddressSet.getAddressRanges();
		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			Address min = range.getMinAddress();
			Address max = range.getMaxAddress();
			Instruction instr = listing.getInstructionContaining(min);
			if (instr != null) {
				instructionSet
						.add(new AddressRangeImpl(instr.getMinAddress(), instr.getMaxAddress()));
			}
			InstructionIterator instIter = listing.getInstructions(new AddressSet(min, max), true);
			while (instIter.hasNext()) {
				instr = instIter.next();
				instructionSet
						.add(new AddressRangeImpl(instr.getMinAddress(), instr.getMaxAddress()));
			}
		}
		return instructionSet;
	}

	// **** CODE UNIT methods ****

	/**
	 * <CODE>mergeCodeUnits</CODE> merges all instructions and/or data
	 * (as indicated) in the specified address set from the origin program.
	 * It merges them into the result program. When merging
	 * instructions, the bytes are also replaced if they differ.
	 * This assumes originToResultTranslator maps address spaces and does
	 * not do fine-grained mapping of addresses.
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param byteDiffs address set indicating addresses where the bytes differ
	 * between the result program and the origin program.
	 * The addresses in this set should be derived from the origin program.
	 * @param mergeDataBytes true indicates bytes that differ should be copied when merging Data.
	 * false means don't copy any bytes for Data.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 *
	 * @throws MemoryAccessException if bytes can't be copied.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	public void mergeCodeUnits(AddressSetView originAddressSet, AddressSetView byteDiffs,
			boolean mergeDataBytes, TaskMonitor monitor)
			throws MemoryAccessException, CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge code units.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Applying Code Units...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		ProgramContext originContext = originProgram.getProgramContext();
		ProgramContext resultContext = resultProgram.getProgramContext();
		Register originContextReg = originContext.getBaseContextRegister();
		Register resultContextReg = resultContext.getBaseContextRegister();

		// Expand ranges to keep delay-slots together within origin range
		// May need to expand each range up or down
		originAddressSet = SimpleDiffUtility.expandAddressSetToIncludeFullDelaySlots(originProgram,
			originAddressSet);

		// Don't clear instructions which match (same instruction prototype) so that references
		// are preserved.
		for (AddressRange originRange : originAddressSet.getAddressRanges()) {
			// Get a new address set for this range that does not include any addresses where
			// the origin and result instruction prototypes are the same.
			// The range address set will be used to clear code units.
			AddressSet rangeSet = new AddressSet(originRange);
			InstructionIterator instructions =
				originListing.getInstructions(new AddressSet(originRange), true);
			for (Instruction instruction : instructions) {
				Address resultAddress =
					originToResultTranslator.getAddress(instruction.getMinAddress());
				Instruction resultInstruction = resultListing.getInstructionAt(resultAddress);
				if (!shouldClearInstruction(instruction, resultInstruction)) {
					// Remove any instructions with matching prototypes, so they won't be cleared.
					rangeSet.delete(instruction.getMinAddress(), instruction.getMaxAddress());
				}
			}
			// Clear the code units still in our range set.
			for (AddressRange newOriginRange : rangeSet.getAddressRanges()) {
				AddressRange resultRange = originToResultTranslator.getAddressRange(newOriginRange);

				// Clear any existing code units in the merged program
				// where this code unit needs to go.
				resultListing.clearCodeUnits(resultRange.getMinAddress(),
					resultRange.getMaxAddress(), false);

				try {
					if (resultContextReg != Register.NO_CONTEXT) {
						if (originContextReg != Register.NO_CONTEXT) {
							// Copy context register value
							mergeProgramContext(resultContext, originContext,
								originContext.getBaseContextRegister(), newOriginRange, resultRange,
								monitor);
						}
						else {
							// Clear context register value if it did not exist in original
							resultContext.remove(resultRange.getMinAddress(),
								resultRange.getMaxAddress(), resultContextReg);
						}
					}
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				}
			}
		}

		CodeUnitIterator originSourceCodeUnits = originListing.getCodeUnits(originAddressSet, true);

		// Get each code unit out of the iterator and set it in the merged
		// program if it is an instruction.
		for (long count = 0; originSourceCodeUnits.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			CodeUnit originCodeUnit = originSourceCodeUnits.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage(
					"Applying Code Units...   " + originCodeUnit.getAddressString(true, false));
				count = 0;
			}

			// Note : performMergeInstruction() and performMergeData()
			//        clear the existing code units and then create a
			//        new instruction or data.
			//        May cause the merge code unit to lose info attached
			//        to it.
			if (originCodeUnit instanceof Instruction) {
				Instruction originInstruction = (Instruction) originCodeUnit;
				Address resultAddress =
					originToResultTranslator.getAddress(originInstruction.getMinAddress());
				Instruction resultInstruction = resultListing.getInstructionAt(resultAddress);
				if (resultInstruction == null ||
					!originInstruction.getPrototype().equals(resultInstruction.getPrototype())) {
					performMergeInstruction(originInstruction, byteDiffs);
				}
				else {
					copyInstructionAttributes(originInstruction, resultInstruction);
				}
			}
			else if (originCodeUnit instanceof Data) {
				try {
					performMergeData((Data) originCodeUnit, byteDiffs, mergeDataBytes);
				}
				catch (CodeUnitInsertionException e) {
					infoMsg.append("Diff/Merge can't apply data from " +
						originCodeUnit.getMinAddress() + ". " + e.getMessage());
				}
			}
		}
	}

	private boolean shouldClearInstruction(Instruction instruction, Instruction resultInstruction) {
		if (resultInstruction == null) {
			return true;
		}
		if (!ProgramDiff.equivalentInstructionPrototypes(instruction, resultInstruction)) {
			return true;
		}
		try {
			if (!Arrays.equals(instruction.getBytes(), resultInstruction.getBytes())) {
				return true; // bytes differ
			}
		}
		catch (MemoryAccessException e) {
			String message =
				"ProgramMerge couldn't get the underlying bytes when comparing instructions." +
					" instruction1 is at " + instruction.getAddress().toString(true) +
					". instruction2 is at " + resultInstruction.getAddress().toString(true) +
					".  " + e.getMessage();
			Msg.error(this, message, e);
			return true;
		}
		return false;
	}

	/**
	 * <CODE>performMergeInstruction</CODE> merges the indicated instruction
	 * into the merge program. Before the instruction is created the bytes for
	 * the instruction are copied from program2 to program1.
	 * Corresponding code unit(s) must already be cleared in result program,
	 * as well as having copied context-register value.
	 * @param originInstruction the instruction to be merged
	 * This instruction should be from the origin program.
	 * @param originByteDiffs address set indicating addresses where the bytes differ
	 * between program1 and program2.
	 * The addresses in this set should be from program1.
	 * @throws CodeUnitInsertionException if the instruction can't be created
	 * in the merge program.
	 * @throws MemoryAccessException if bytes can't be copied.
	 */
	private void performMergeInstruction(Instruction originInstruction,
			AddressSetView originByteDiffs) throws MemoryAccessException {

		Address originMin = originInstruction.getMinAddress();
		Address resultMin = originToResultTranslator.getAddress(originMin);

		if (originInstruction.isInDelaySlot()) {
			// delay slots must be created as part of its delay-slotted predecessor
			Instruction resultInst = resultListing.getInstructionAt(resultMin);
			if (resultInst != null && resultInst.isInDelaySlot()) {
				copyInstructionAttributes(originInstruction, resultInst);
			}
			return;
		}

		int bytesLength;
		Address originMax;
		if (originInstruction.getDelaySlotDepth() != 0) {
			// must include delay slots for byte copy
			originMax = SimpleDiffUtility.getEndOfDelaySlots(originInstruction);
			bytesLength = (int) originMax.subtract(originMin);
		}
		else {
			originMax = originInstruction.getMaxAddress();
			bytesLength = originInstruction.getLength();
		}

		Address resultMax = originToResultTranslator.getAddress(originMax);

		MemoryBlock resultBlock = resultProgram.getMemory().getBlock(resultMin);
		boolean initializedBytes = (resultBlock != null) ? resultBlock.isInitialized() : false;

		if (!initializedBytes) {
			infoMsg.append("Diff/Merge can't apply instruction from " + originMin + " to " +
				resultMin + " since it needs initialized memory");
			return;
		}

		// If there are byte differences for this instruction then the
		// bytes need to get copied even though the user did not indicate to.
		if (bytesAreDifferent(originByteDiffs, originMin, resultMin, bytesLength)) { // FIXME
			// Copy all the bytes for the instruction if any bytes differ.
			ProgramMemoryUtil.copyBytesInRanges(resultProgram, originProgram, resultMin, resultMax);
		}

		Instruction newInst;
		if (originInstruction.getDelaySlotDepth() != 0) {
			newInst = disassembleDelaySlottedInstruction(resultProgram, resultMin);
		}
		else {
			newInst = disassembleNonDelaySlotInstruction(resultProgram, resultMin);
		}
		if (newInst == null) {
			return;
		}

		copyInstructionAttributes(originInstruction, newInst);
	}

	private void copyInstructionAttributes(Instruction originInstruction,
			Instruction targetInstruction) {
		// If instruction has modified fall through, then change it
		Address oldFallThrough = originInstruction.getFallThrough();
		Address newFallThrough = originToResultTranslator.getAddress(oldFallThrough);
		if (!SystemUtilities.isEqual(targetInstruction.getFallThrough(), newFallThrough)) {
			if (originInstruction.isFallThroughOverridden()) {
				targetInstruction.setFallThrough(newFallThrough);
			}
			else {
				targetInstruction.clearFallThroughOverride();
			}
		}

		FlowOverride originFlowOverride = originInstruction.getFlowOverride();
		FlowOverride targetFlowOverride = targetInstruction.getFlowOverride();
		if (originFlowOverride != targetFlowOverride) {
			targetInstruction.setFlowOverride(originFlowOverride);
		}
	}

	private Instruction disassembleDelaySlottedInstruction(Program program, Address addr) {
		// Use heavyweight disassembler for delay slotted instruction
		AddressSet restrictedSet = new AddressSet(addr);
		Disassembler disassembler =
			Disassembler.getDisassembler(program, TaskMonitorAdapter.DUMMY_MONITOR, null);
		disassembler.disassemble(addr, restrictedSet, false);
		return program.getListing().getInstructionAt(addr);
	}

	private Instruction disassembleNonDelaySlotInstruction(Program program, Address addr) {
		// Use lightweight disassembler for simple case
		DisassemblerContextImpl context = new DisassemblerContextImpl(program.getProgramContext());
		context.flowStart(addr);
		try {
			InstructionPrototype proto = program.getLanguage()
					.parse(new DumbMemBufferImpl(program.getMemory(), addr), context, false);
			return resultListing.createInstruction(addr, proto,
				new DumbMemBufferImpl(program.getMemory(), addr),
				new ProgramProcessorContext(program.getProgramContext(), addr));
		}
		catch (Exception e) {
			program.getBookmarkManager()
					.setBookmark(addr, BookmarkType.ERROR, Disassembler.ERROR_BOOKMARK_CATEGORY,
						"Diff/Merge applied bad instruction");
		}
		return null;
	}

	private boolean bytesAreDifferent(AddressSetView originByteDiffs, Address originMin,
			Address resultMin, int byteCnt) throws MemoryAccessException {
		if (originByteDiffs != null) {
			AddressSet resultByteDiffs = originToResultTranslator.getAddressSet(originByteDiffs);
			return resultByteDiffs.intersects(new AddressSet(resultMin, resultMin.add(byteCnt)));
		}
		byte[] originBytes = new byte[byteCnt];
		originProgram.getMemory().getBytes(originMin, originBytes);
		byte[] resultBytes = new byte[byteCnt];
		resultProgram.getMemory().getBytes(resultMin, resultBytes);
		return !Arrays.equals(originBytes, resultBytes);
	}

	/**
	 * <CODE>performMergeData</CODE> merges the indicated defined data
	 * into the merge program. The bytes in the merge program are not affected
	 * by this method.
	 * Corresponding code unit(s) must already be cleared in result program.
	 * @param originData the defined data to be merged
	 * This data should be from the origin program.
	 * @param originByteDiffs address set indicating addresses where the bytes differ
	 * between the result program and the origin program.
	 * This addresses in this set should be derived from the origin program.
	 * @param copyBytes true indicates bytes that differ should be copied.
	 * false means don't copy any bytes.
	 * @throws CodeUnitInsertionException if the defined data can't be created
	 * in the merge program.
	 */
	private void performMergeData(Data originData, AddressSetView originByteDiffs,
			boolean copyBytes) throws CodeUnitInsertionException, MemoryAccessException {

		Address originMin = originData.getMinAddress();
		Address originMax = originData.getMaxAddress();
		Address resultMin = originToResultTranslator.getAddress(originMin);
		Address resultMax = originToResultTranslator.getAddress(originMax);
		DataType dt = originData.getDataType();
		boolean hasNewData = false;

		// If there are byte differences for this instruction then the
		// bytes need to get copied even though the user did not indicate to.
		if (copyBytes &&
			bytesAreDifferent(originByteDiffs, originMin, resultMin, originData.getLength())) {
			// Copy all the bytes for the instruction if any bytes differ.
			ProgramMemoryUtil.copyBytesInRanges(resultProgram, originProgram, resultMin, resultMax);
		}

		if (!(dt.equals(DataType.DEFAULT))) {
			resultListing.createData(resultMin, originData.getDataType(), originData.getLength());
			hasNewData = true;
		}
		if (hasNewData) {
			Data newData = resultListing.getDataAt(resultMin);
			String[] settingNames = originData.getNames();
			for (String settingName : settingNames) {
				Object obj = originData.getValue(settingName);
				if (obj != null) {
					newData.setValue(settingName, obj);
				}
			}
		}
	}

	// **** EQUATE methods ****

	/**
	 * <CODE>mergeEquates</CODE> merges the equate differences in the specified
	 * address set.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 *
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	public void mergeEquates(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge equates.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Applying Equates...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		AddressIterator addresses = originAddressSet.getAddresses(true);
		// Get each equate out of the equate address iterator and set it in the merged program.
		for (long count = 0; addresses.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			Address address = addresses.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage("Applying Equates...   " + address.toString(true, false));
				count = 0;
			}
			mergeEquates(address);
		}
	}

	/**
	 * <CODE>mergeEquate</CODE> replaces the current equates in program1 with those in program2.
	 * @param originAddress the address where the equates should be merged.
	 * This address should be derived from the origin program.
	 * @param opIndex the operand index where the equates should be merged.
	 * @param value the scalar value where the equate is used.
	 */
	public void mergeEquate(Address originAddress, int opIndex, long value) {
		EquateTable resultEquateTable = resultProgram.getEquateTable();
		EquateTable originEquateTable = originProgram.getEquateTable();
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		Equate resultEquate = resultEquateTable.getEquate(resultAddress, opIndex, value);
		Equate originEquate = originEquateTable.getEquate(originAddress, opIndex, value);
		if (SystemUtilities.isEqual(resultEquate, originEquate)) {
			return;
		}
		if (resultEquate != null) {
			resultEquate.removeReference(resultAddress, opIndex);
			if (resultEquate.getReferenceCount() == 0) {
				resultEquateTable.removeEquate(resultEquate.getName());
			}
		}
		if (originEquate != null) {
			Equate uniqueEquate = getUniqueEquate(resultEquateTable, originEquate.getName(), value);
			uniqueEquate.addReference(resultAddress, opIndex);
		}
	}

	private Equate getUniqueEquate(EquateTable et, String name, long value) {
		for (int count = -1; count <= Integer.MAX_VALUE; count++) {
			String newName = name + ((count >= 0) ? SYMBOL_CONFLICT_SUFFIX : "") +
				((count > 0) ? Integer.toString(count) : "");
			Equate eq = et.getEquate(newName);
			if (eq == null) {
				try {
					Equate equate = et.createEquate(newName, value);
					if (!newName.equals(name)) {
						saveDuplicateEquate(equate, name);
					}
					return equate;
				}
				catch (DuplicateNameException e) {
					Equate equate = et.getEquate(newName);
					if (equate != null && equate.getValue() == value) {
						return equate;
					}
					continue;
				}
				catch (InvalidInputException e) {
					throw new RuntimeException(
						"Can't merge equate with name [" + name + "] and value [" + value + "].",
						e);
				}
			}
			else if (eq.getValue() == value) {
				return eq;
			}
		}
		throw new RuntimeException(
			"Can't merge equate with name [" + name + "] and value [" + value + "].");
	}

	/**
	 * <CODE>mergeEquates</CODE> merges all equates for the indicated
	 * address from the second program. It merges them into the merge program.
	 *
	 * @param originAddress the address where the equates are to be merged.
	 * This address should be derived from the origin program.
	 */
	void mergeEquates(Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		if (resultAddress == null) {
			return;
		}
		EquateTable originEt = originProgram.getEquateTable();
		EquateTable resultEt = resultProgram.getEquateTable();
		// Check each operand field
		for (int opIndex = 0; opIndex < Program.MAX_OPERANDS; opIndex++) {
			List<Equate> originList = originEt.getEquates(originAddress, opIndex);
			Equate originEquate =
				(originList.size() > 0) ? originList.get(originList.size() - 1) : null;
			List<Equate> resultList = resultEt.getEquates(resultAddress, opIndex);
			Equate resultEquate =
				(resultList.size() > 0) ? resultList.get(resultList.size() - 1) : null;
			if ((originEquate == null && resultEquate == null) ||
				(resultEquate != null && resultEquate.equals(originEquate))) {
				continue; // Do nothing.
			}
			if (originEquate != null) {
				long value = originEquate.getValue();
				mergeEquate(resultAddress, opIndex, value);
			}
			else if (resultEquate != null) {
				// Clear the old equate.
				resultEquate.removeReference(resultAddress, opIndex);
				if (resultEquate.getReferenceCount() == 0) {
					resultEt.removeEquate(resultEquate.getName());
				}
			}
		}
	}

	/**
	 * @param dupEquate
	 * @param desiredName
	 */
	private void saveDuplicateEquate(Equate dupEquate, String desiredName) {
		dupEquates.put(dupEquate.getName(), new DupEquate(dupEquate, desiredName));
	}

	/**
	 *
	 */
	void reApplyDuplicateEquates() {
		for (String conflictName : dupEquates.keySet()) {
			DupEquate dupEquate = dupEquates.get(conflictName);
			Equate equate = dupEquate.equate;
			String desiredName = dupEquate.preferredName;
			try {
				equate.renameEquate(desiredName);
				dupEquates.remove(conflictName);
			}
			catch (DuplicateNameException e) {
				continue; // Leaves it in the hashtable
			}
			catch (InvalidInputException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				errorMsg.append("InvalidInputException re-applying duplicate equates: " +
					e.getMessage() + "\n");
			}
		}
	}

	private class DupEquate {
		Equate equate;
		String preferredName;

		DupEquate(Equate equate, String preferredName) {
			this.equate = equate;
			this.preferredName = preferredName;
		}
	}

	/**
	 *
	 */
	String getDuplicateEquatesInfo() {
		StringBuffer buf = new StringBuffer();
		for (String conflictName : dupEquates.keySet()) {
			DupEquate dupEquate = dupEquates.get(conflictName);
			Equate equate = dupEquate.equate;
			String desiredName = dupEquate.preferredName;
			String msg = "Equate '" + desiredName + "' with value of " + equate.getValue() +
				" renamed to '" + conflictName + "' due to merge conflict.\n";
			buf.append(msg);
		}
		return buf.toString();
	}

	/**
	 *
	 */
	void clearDuplicateEquates() {
		dupEquates.clear();
	}

	// **** REFERENCE methods ****

	/**
	 * <CODE>replaceReferences</CODE> replaces all references in
	 * program1 for the specified address set with those in program2.
	 * If an equivalent reference already exists then it is updated to match the
	 * new reference.
	 * <br> Note: All reference types (memory, stack, external) get replaced
	 * where possible. i.e. If a function or variable doesn't exist for a
	 * variable reference then it will not be able to replace the reference.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if the user cancels the replace via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	public void replaceReferences(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		replaceReferences(originAddressSet, false, monitor);
	}

	/**
	 * <CODE>replaceReferences</CODE> replaces all references in
	 * program1 for the specified address set with the references from program2.
	 * If an equivalent reference already exists then it is updated to match the
	 * new reference.
	 * <br> Note: All reference types (memory, stack, external) get replaced
	 * where possible. i.e. If a function or variable doesn't exist for a
	 * variable reference then it will not be able to replace the reference.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param onlyKeepDefaults true indicates to replace all references with only
	 * the default references from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if the user cancels the replace via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	public void replaceReferences(AddressSetView originAddressSet, boolean onlyKeepDefaults,
			TaskMonitor monitor) throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't replace references.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Replacing References...");
		if (originAddressSet.isEmpty()) {
			return;
		}
		AddressSet resultAddressSet = originToResultTranslator.getAddressSet(originAddressSet);

		ReferenceManager originRM = originProgram.getReferenceManager();
		ReferenceManager resultRM = resultProgram.getReferenceManager();
		AddressIterator originIter = originRM.getReferenceSourceIterator(originAddressSet, true);
		AddressIterator resultIter = resultRM.getReferenceSourceIterator(resultAddressSet, true);
		AddressIteratorConverter convertedResultIter =
			new AddressIteratorConverter(resultProgram, resultIter, originProgram);
		// Determine where to get the new code units from.
		MultiAddressIterator originRefAddrIter =
			new MultiAddressIterator(new AddressIterator[] { convertedResultIter, originIter });
		for (long count = 0; originRefAddrIter.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			Address originAddress = originRefAddrIter.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage("Replacing References...   " + originAddress.toString(true));
				count = 0;
			}
			replaceRefs(originAddress, onlyKeepDefaults);
		}
	}

	/**
	 *
	 * @param resultAddress
	 * This address should be derived from program 1.
	 */
	private void replaceRefs(Address originAddress, boolean defaultsOnly) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		ReferenceManager originalRM = originProgram.getReferenceManager();
		ReferenceManager resultRM = resultProgram.getReferenceManager();
		Reference[] originRefs = originalRM.getReferencesFrom(originAddress);
		Reference[] resultRefs = resultRM.getReferencesFrom(resultAddress);
		HashMap<Reference, Reference> originToResultMap = new HashMap<>(); // OriginRef, ResultRef
		// Determine the result references to keep that match the origin references.
		for (Reference origRef : originRefs) {
			SourceType source = origRef.getSource();
			if (defaultsOnly && source != SourceType.DEFAULT) {
				continue; // Don't hold onto non-defaults.
			}
			Reference resultRef = DiffUtility.getReference(originToResultTranslator, origRef);
			originToResultMap.put(origRef, resultRef);
		}
		// Remove references we don't need any more or those that are there but not the same.
		for (Reference resultRef : resultRefs) {
			// Leave fallthroughs as they are, so the code unit merge can handle them.
			if (resultRef.getReferenceType().isFallthrough()) {
				continue;
			}
			if (!originToResultMap.containsKey(resultRef)) {
				resultRM.delete(resultRef);
			}
		}
		// Add the references that aren't there yet and those that weren't the same.

		for (Reference originRef : originToResultMap.keySet()) {
			// Leave fall-through as they are, so the code unit merge can handle them.
			if (originRef.getReferenceType().isFallthrough()) {
				continue;
			}
			Reference resultRef = originToResultMap.get(originRef);
			replaceReference(resultRef, originRef);
		}
	}

	/**
	 * <CODE>mergeReferences</CODE> merges the references in
	 * program1 for the specified address set with the references from program2.
	 * If an equivalent reference already exists then it is updated to match the
	 * new reference if possible. A merge of references prevents the loss of any
	 * non-default references already in the result program.
	 * <br> Important: Fallthrough references will not be merged by this method.
	 * Fallthroughs are handled by merging code units.
	 * <br> Note: All reference types (memory, stack, external) get replaced
	 * where possible. i.e. If a function or variable doesn't exist for a
	 * variable reference then it will not be able to replace the reference.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param onlyKeepDefaults true indicates to merge only the default references
	 * from the origin program into the result program. Non-default references will not be merged.
	 * false indicates merge all references except fallthroughs.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if the user cancels the replace via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	public void mergeReferences(AddressSetView originAddressSet, boolean onlyKeepDefaults,
			TaskMonitor monitor) throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge references.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Merging References...");
		if (originAddressSet.isEmpty()) {
			return;
		}
		AddressSet resultAddressSet = originToResultTranslator.getAddressSet(originAddressSet);

		ReferenceManager originRM = originProgram.getReferenceManager();
		ReferenceManager resultRM = resultProgram.getReferenceManager();
		AddressIterator originIter = originRM.getReferenceSourceIterator(originAddressSet, true);
		AddressIterator resultIter = resultRM.getReferenceSourceIterator(resultAddressSet, true);
		AddressIteratorConverter convertedResultIter =
			new AddressIteratorConverter(resultProgram, resultIter, originProgram);
		// Determine where to get the new code units from.
		MultiAddressIterator originRefAddrIter =
			new MultiAddressIterator(new AddressIterator[] { convertedResultIter, originIter });
		for (long count = 0; originRefAddrIter.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			Address originAddress = originRefAddrIter.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage("Merging References...   " + originAddress.toString(true));
				count = 0;
			}
			mergeRefs(originAddress, onlyKeepDefaults);
		}
	}

	private void mergeRefs(Address originAddress, boolean defaultsOnly) {
		ReferenceManager originalRM = originProgram.getReferenceManager();
		Reference[] originRefs = originalRM.getReferencesFrom(originAddress);
		HashMap<Reference, Reference> originToResultMap = new HashMap<>(); // OriginRef, ResultRef
		// Determine the result references to keep that match the origin references.
		for (Reference origRef : originRefs) {
			SourceType source = origRef.getSource();
			if (defaultsOnly && source != SourceType.DEFAULT) {
				continue; // Don't hold onto non-defaults.
			}
			Reference resultRef = DiffUtility.getReference(originToResultTranslator, origRef);
			originToResultMap.put(origRef, resultRef);
		}
		// Add the references that aren't there yet and those that weren't the same.
		for (Reference originRef : originToResultMap.keySet()) {
			Reference resultRef = originToResultMap.get(originRef);
			// Leave fallthroughs as they are, so the code unit merge can handle them.
			if (originRef.getReferenceType().isFallthrough()) {
				continue;
			}
			replaceReference(resultRef, originRef);
		}
	}

	private void replaceReferences(CodeUnit originCu, int opIndex) {
		Address resultAddress = originToResultTranslator.getAddress(originCu.getMinAddress());
		resultCu = resultListing.getCodeUnitAt(resultAddress);
		if (opIndex > resultCu.getNumOperands()) {
			return;
		}
		ReferenceManager resultRM = resultProgram.getReferenceManager();
		Reference[] resultRefs = resultRM.getReferencesFrom(resultCu.getMinAddress(), opIndex);
		Reference[] originRefs = originProgram.getReferenceManager()
				.getReferencesFrom(originCu.getMinAddress(), opIndex);
		HashMap<Reference, Reference> resultsToKeep = new HashMap<>(); // key=OriginRef, value=ResultRef
		// Determine the result references to keep that match the origin references.
		for (Reference originRef : originRefs) {
			Reference resultRef = DiffUtility.getReference(originToResultTranslator, originRef);
			resultsToKeep.put(originRef, resultRef); // resultRef may be null
		}
		// Remove references we don't need any more or those that are there but not the same.
		for (Reference resultRef : resultRefs) {
			if (!resultsToKeep.containsValue(resultRef)) {
				resultRM.delete(resultRef);
			}
		}
		// Add the references that aren't there yet and those that weren't the same.
		for (Reference originRef : resultsToKeep.keySet()) {
			Reference resultRef = resultsToKeep.get(originRef);
			replaceReference(resultRef, originRef);
		}
	}

	/**
	 * <CODE>replaceReferences</CODE> replaces all references in
	 * program1 for the specified address and operand index with those in program2.
	 * If an equivalent reference already exists then it is updated to match the
	 * new reference.
	 * <br> Note: All reference types (memory, stack, external) get replaced
	 * where possible. i.e. If a function or variable doesn't exist for a
	 * variable reference then it will not be able to replace the reference.
	 *
	 * @param originAddress the "from" address where references are to be replaced
	 * @param operandIndex the operand of the code unit at the address where
	 * references are to be replaced.
	 */
	public void replaceReferences(Address originAddress, int operandIndex) {
		CodeUnit fromCu = originListing.getCodeUnitAt(originAddress);
		replaceReferences(fromCu, operandIndex);
	}

	/**
	 * Replaces the reference in program1 with the reference from the origin program.
	 * @param resultRef the program1 reference to be replaced.
	 * @param originRef the program2 reference used to replace what's in program1.
	 * @return the resulting reference in program1. null if reference is removed
	 * by the replace.
	 */
	public Reference replaceReference(Reference resultRef, Reference originRef) {
		ReferenceManager rm = resultProgram.getReferenceManager();
		if (originRef != null) {
			if (originRef.isExternalReference()) {
				updateExternalLocation(resultProgram, (ExternalReference) originRef);
			}
			return addReference(originRef, -1, true);
		}

		rm.delete(resultRef);
		return null;
	}

	private void updateExternalLocation(Program toPgm, ExternalReference fromRef) {
		ExternalLocation fromExtLoc = fromRef.getExternalLocation();
		Namespace fromNamespace = fromExtLoc.getParentNameSpace();
		String fromExtLabel = fromExtLoc.getLabel();
		Address fromExtAddr = fromExtLoc.getAddress();
		SourceType fromSourceType = fromExtLoc.getSource();

		ExternalManager toExtMgr = toPgm.getExternalManager();
		try {
			Program fromPgm = fromExtLoc.getSymbol().getProgram();
			Namespace toNamespace = DiffUtility.createNamespace(fromPgm, fromNamespace, toPgm);
			ExternalLocation toExternalLocation =
				SimpleDiffUtility.getMatchingExternalLocation(fromPgm, fromExtLoc, toPgm);
			if (toExternalLocation == null) {
				toExtMgr.addExtLocation(toNamespace, fromExtLabel, fromExtAddr, fromSourceType);
			}
			else {
				String toExtLabel = toExternalLocation.getLabel();
				// Found the named external and updated its external address if necessary.
				toExternalLocation.setLocation(toExtLabel, fromExtAddr, fromExtLoc.getSource());
			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append(
				"InvalidInputException updating external location: " + e.getMessage() + "\n");
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append(
				"DuplicateNameException updating external location: " + e.getMessage() + "\n");
		}
	}

	/**
	 * Replaces the reference in program1 with the reference from the origin program.
	 * @param resultRef the program1 reference to be replaced.
	 * @param originRef the program2 reference used to replace what's in program1.
	 * @param toSymbolID ID of the symbol in program1 the resulting reference is to.
	 * @return the resulting reference in program1. null if reference is removed
	 * by the replace.
	 */
	public Reference replaceReference(Reference resultRef, Reference originRef, long toSymbolID) {
		ReferenceManager rm = resultProgram.getReferenceManager();
		if (resultRef != null) {
			// Removing ref.
			rm.delete(resultRef);
		}
		if (originRef != null) {
			Address toAddress = originToResultTranslator.getAddress(originRef.getToAddress());
			Symbol resultToSymbol = resultProgram.getSymbolTable().getSymbol(toSymbolID);
			if (resultToSymbol != null && !resultToSymbol.getAddress().equals(toAddress)) {
				resultToSymbol = null;
			}
			resultRef = DiffUtility.createReference(originProgram, originRef, resultProgram);
			if (resultToSymbol != null) {
				rm.setAssociation(resultToSymbol, resultRef);
			}
		}
		else {
			resultRef = null;
		}
		return resultRef;
	}

	/**
	 * <CODE>addReference</CODE> creates a reference in program1 that is equivalent
	 * to the one specified as a parameter. If a symbol ID is specified, the
	 * reference will refer to the symbol in program1 with that ID. If the reference
	 * is an external reference, then the external location associated with it can be replaced
	 * also by setting the replace external location flag.
	 * @param originRef the reference equivalent to the one to be created.
	 * @param toSymbolID ID of the symbol to referred to. null indicates don't
	 * refer directly to a symbol.
	 * @param replaceExtLoc the replace external location flag. true indicates to replace the
	 * external location, if applicable, with the one defined for the reference passed to this method.
	 * @return the reference that was created. null if none created.
	 */
	public Reference addReference(Reference originRef, long toSymbolID, boolean replaceExtLoc) {
		ReferenceManager rm = resultProgram.getReferenceManager();
		Reference resultRef = null;
		if (originRef != null) {
			Symbol resultToSymbol = resultProgram.getSymbolTable().getSymbol(toSymbolID);

			if (originRef.isExternalReference()) {
				ExternalReference origExtRef = (ExternalReference) originRef;
				ExternalLocation origExtLoc = origExtRef.getExternalLocation();

				if (origExtLoc == null) {
					return null;
				}

				ExternalLocation resultExtLoc = findExternalLocation(origExtLoc, resultToSymbol);

				if (replaceExtLoc && resultExtLoc != null) {
					try {
						String extLabel = origExtLoc.getLabel();
						Address extAddr = origExtLoc.getAddress();
						resultExtLoc.setLocation(extLabel, extAddr, origExtLoc.getSource());
					}
					catch (DuplicateNameException e) {
						Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
						errorMsg.append(
							"DuplicateNameException adding reference: " + e.getMessage() + "\n");
					}
					catch (InvalidInputException e) {
						Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
						errorMsg.append(
							"InvalidInputException adding reference: " + e.getMessage() + "\n");
					}
				}
			}

			resultRef = DiffUtility.createReference(originProgram, originRef, resultProgram);

			if (resultToSymbol != null) {
				rm.setAssociation(resultToSymbol, resultRef);
			}
		}
		return resultRef;
	}

	private ExternalLocation findExternalLocation(ExternalLocation origExtLoc,
			Symbol resultToSymbol) {
		if (resultToSymbol != null) {
			ExternalLocation toLocation =
				resultProgram.getExternalManager().getExternalLocation(resultToSymbol);
			if (toLocation != null) {
				return toLocation;
			}
		}
		try {
			return DiffUtility.createExtLocation(originProgram, origExtLoc, resultProgram);
		}
		catch (InvalidInputException | DuplicateNameException e) {
			// can't create one
		}
		return null;
	}

	/**
	 * <CODE>replaceFallThroughs</CODE> replaces all fallthroughs in
	 * program1 for the specified address set with those in program2 where they differ.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if the user cancels the replace via the monitor.
	 */
	public void replaceFallThroughs(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException {
		if (originAddressSet.isEmpty()) {
			return;
		}
		monitor.setMessage("Replacing Fallthroughs...");
		long max = originAddressSet.getNumAddresses();
		monitor.initialize(max);

		CodeUnitIterator cuIterator2 = originListing.getCodeUnits(originAddressSet, true);
		for (long count = 0; cuIterator2.hasNext(); count++) {
			monitor.checkCanceled();
			CodeUnit cu2 = cuIterator2.next();
			Address originMinAddress = cu2.getMinAddress();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage(
					"Replacing FallThroughs...   " + originMinAddress.toString(true));
				count = 0;
			}
			replaceFallThrough(originMinAddress);
			monitor.setProgress(monitor.getProgress() + cu2.getLength());
		}
		monitor.setProgress(max);
	}

	private void replaceFallThrough(Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		Instruction resultInstruction = resultListing.getInstructionAt(resultAddress);
		Instruction originInstruction = originListing.getInstructionAt(originAddress);
		if (originInstruction == null || resultInstruction == null) {
			return;
		}
		boolean resultOverridden = resultInstruction.isFallThroughOverridden();
		boolean originOverridden = originInstruction.isFallThroughOverridden();
		if (!resultOverridden && !originOverridden) {
			return; // Neither has overridden the fallthrough
		}
		Address resultFallThrough = resultInstruction.getFallThrough();
		Address originFallThrough = originInstruction.getFallThrough();
		Address originFTCompatibleWithResult =
			originToResultTranslator.getAddress(originFallThrough);
		if (SystemUtilities.isEqual(resultFallThrough, originFTCompatibleWithResult)) {
			return;
		}
		if (!originOverridden) {
			resultInstruction.clearFallThroughOverride();
		}
		else {
			resultInstruction.setFallThrough(originFTCompatibleWithResult);
		}
	}

	// **** COMMENT methods ****

	/** <CODE>mergeComment</CODE> merges/replaces comments of the indicated
	 * type wherever they occur in the specified address set.
	 * @param originAddressSet the addresses where comments should be merged/replaced.
	 * The addresses in this set should be from the origin program.
	 * @param type ProgramMergeFilter comment type.
	 * The comment type can be PLATE, PRE, EOL, REPEATABLE, POST.
	 * @param both true means merge both program1 and program2 comments.
	 * false means replace the program1 comment with the program2 comment.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void mergeComment(AddressSet originAddressSet, int type, boolean both,
			TaskMonitor monitor) throws CancelledException {
		mergeCommentType(originAddressSet, type,
			both ? ProgramMergeFilter.MERGE : ProgramMergeFilter.REPLACE, monitor);
	}

	/**
	 * <CODE>mergeCommentType</CODE> merges/replaces comments of the indicated
	 * type wherever they occur in the specified address set.
	 * It merges them from program2 into program1.
	 * This merges eol, pre, post, repeatable, and plate comments.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from the origin program.
	 * @param type the comment type. PLATE, PRE, EOL, REPEATABLE, POST
	 * @param setting how to merge. IGNORE, REPLACE, MERGE
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void mergeCommentType(AddressSetView originAddressSet, int type, int setting,
			TaskMonitor monitor) throws CancelledException {
		if ((setting != ProgramMergeFilter.REPLACE) && (setting != ProgramMergeFilter.MERGE)) {
			return;
		}

		String typeStr = "Unknown";
		int cuCommentType;
		switch (type) {
			case ProgramMergeFilter.PLATE_COMMENTS:
				typeStr = "Plate";
				cuCommentType = CodeUnit.PLATE_COMMENT;
				break;
			case ProgramMergeFilter.PRE_COMMENTS:
				typeStr = "Pre";
				cuCommentType = CodeUnit.PRE_COMMENT;
				break;
			case ProgramMergeFilter.EOL_COMMENTS:
				typeStr = "EOL";
				cuCommentType = CodeUnit.EOL_COMMENT;
				break;
			case ProgramMergeFilter.REPEATABLE_COMMENTS:
				typeStr = "Repeatable";
				cuCommentType = CodeUnit.REPEATABLE_COMMENT;
				break;
			case ProgramMergeFilter.POST_COMMENTS:
				typeStr = "Post";
				cuCommentType = CodeUnit.POST_COMMENT;
				break;
			default:
				throw new AssertException("Unrecognized comment type: " + type);
		}

		monitor.setMessage("Applying " + typeStr + " comments...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		monitor.checkCanceled();

		boolean both = (setting == ProgramMergeFilter.MERGE) ? true : false;
		String prefix = both ? "Merging" : "Replacing";
		AddressIterator addrIter = originAddressSet.getAddresses(true);
		for (long count = 0; addrIter.hasNext(); count++) {
			monitor.checkCanceled();
			Address originAddress = addrIter.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage(
					prefix + " " + typeStr + " comments...   " + originAddress.toString(true));
				count = 0;
			}
			// Determine where to get the Comments from.
			if (both) {
				mergeComments(cuCommentType, originAddress);
			}
			else {
				replaceComment(cuCommentType, originAddress);
			}
		}
	}

	/**
	 * <CODE>mergeComments</CODE> merges the comment of the indicated
	 * type in program1 with the comment in program2 at the specified address.
	 * @param commentType comment type to merge (from CodeUnit class).
	 * <br>EOL_COMMENT, PRE_COMMENT, POST_COMMENT, REPEATABLE_COMMENT, OR PLATE_COMMENT.
	 * @param originAddress the address
	 * This address should be derived from the origin program.
	 */
	public void mergeComments(int commentType, Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		String resultComment = resultListing.getComment(commentType, resultAddress);
		String origComment = originListing.getComment(commentType, originAddress);
		String newComment = StringUtilities.mergeStrings(resultComment, origComment);
		resultListing.setComment(resultAddress, commentType, newComment);
	}

	/**
	 * <CODE>replaceComment</CODE> replaces the comment of the indicated
	 * type in program1 with the comment in program2 at the specified address.
	 * @param commentType comment type to replace (from CodeUnit class).
	 * <br>EOL_COMMENT, PRE_COMMENT, POST_COMMENT, REPEATABLE_COMMENT, OR PLATE_COMMENT.
	 * @param originAddress the address
	 * This address should be derived from the origin program.
	 */
	public void replaceComment(int commentType, Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		String origComment = originListing.getComment(commentType, originAddress);
		resultListing.setComment(resultAddress, commentType, origComment);
	}

	// **** FUNCTION TAG methods ****

	/**
	 * Merges/replaces tags of program2 into program1. When merging, tags that are in
	 * conflict are replaced according to the user setting (ignore, replace, merge).
	 *
	 * @param originAddressSet the addresses to be merged.
	 * @param setting how to merge. IGNORE, REPLACE, MERGE
	 * @param discardTags tags to keep out of the final result
	 * @param keepTags tags to add to the final result
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void applyFunctionTagChanges(AddressSetView originAddressSet, int setting,
			Set<FunctionTag> discardTags, Set<FunctionTag> keepTags, TaskMonitor monitor)
			throws CancelledException {

		if ((setting != ProgramMergeFilter.REPLACE) && (setting != ProgramMergeFilter.MERGE)) {
			return;
		}

		monitor.setMessage("Applying function tags...");
		if (originAddressSet.isEmpty()) {
			return;
		}
		monitor.checkCanceled();

		AddressIterator addrIter = originAddressSet.getAddresses(true);
		for (long count = 0; addrIter.hasNext(); count++) {
			monitor.checkCanceled();
			Address originAddress = addrIter.next();

			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage(
					setting + " " + " function tags...   " + originAddress.toString(true));
				count = 0;
			}

			// This is the meat; either merge or replace depending on the user selection.
			if (setting == ProgramMergeFilter.MERGE) {
				mergeFunctionTags(originAddress, discardTags, keepTags);
			}
			else if (setting == ProgramMergeFilter.REPLACE) {
				replaceFunctionTags(originAddress);
			}
		}
	}

	/**
	 * Combines function tags in Original with Result, making sure that all tags in the
	 * keepTags list are included, while removing any in the discardTags list.
	 *
	 * @param originAddress the address
	 * @param discardTags tags to discard from the result
	 * @param keepTags tags to add to the result
	 */
	private void mergeFunctionTags(Address originAddress, Set<FunctionTag> discardTags,
			Set<FunctionTag> keepTags) {

		// Get all the tags in the Result program for the given function.
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		Function resultFunction = resultListing.getFunctionContaining(resultAddress);
		if (resultFunction == null) {
			return;
		}
		Set<FunctionTag> resultTags = resultFunction.getTags();

		// Now get all tags in Original, and add them to Result function if they haven't already
		// been added.
		Function originalFunction = originListing.getFunctionContaining(originAddress);
		if (originalFunction != null) {
			Collection<FunctionTag> origTags = originalFunction.getTags();
			for (FunctionTag tag : origTags) {
				if (!containsTag(resultTags, tag.getName())) {
					resultFunction.addTag(tag.getName());
				}
			}
		}

		// Now we have to handle the special cases of a list of tags to discard or keep having
		// been supplied. To start, get the list of tags in Result again, since they've changed.
		resultTags = resultListing.getFunctionContaining(resultAddress).getTags();

		// Now discard any tags we've been told to remove.
		if (discardTags != null) {
			Set<String> tagNames = getTagNames(discardTags);
			Iterator<FunctionTag> iter = resultTags.iterator();
			while (iter.hasNext()) {
				FunctionTag tag = iter.next();
				if (tagNames.contains(tag.getName())) {
					resultFunction.removeTag(tag.getName());

					// Interesting Case Alert!
					//
					// This merge case will only occur when one user has deleted a tag and the
					// other has decided to add it to a function. So with that in mind, the following
					// situation is possible:
					//
					// If the merge panel is up and the user selects to keep the version that
					// has the tag, THEN subsequently selects the option where the tag was
					// deleted, we have a problem. When the first option was selected the tag
					// would have been added to the Result database in two places: the tag table
					// itself, and the tag mapping table. So if the user then opts for the other
					// option, we have to not only remove it from the mapping table, but also
					// from the tag table. HOWEVER, we should only remove it from the tag table
					// if no other function is using it.
					removeTagIfUnassigned(tag);
				}
			}
		}

		// And add back any tags we've been told to keep.
		if (keepTags != null) {
			Set<String> tagNames = getTagNames(keepTags);
			for (String tagName : tagNames) {
				if (!containsTag(resultTags, tagName)) {
					resultFunction.addTag(tagName);
				}
			}
		}
	}

	/**
	 * Removes the given tag from the program if it is not currently being used by
	 * any functions.
	 *
	 * @param tag the tag to remove
	 */
	private void removeTagIfUnassigned(FunctionTag tag) {
		FunctionManagerDB functionManagerDB =
			(FunctionManagerDB) resultProgram.getFunctionManager();
		FunctionTagManager functionTagManager = functionManagerDB.getFunctionTagManager();
		if (!functionTagManager.isTagAssigned(tag.getName())) {
			tag.delete();
		}
	}

	/**
	 * Returns true if the given set of tags contains one with the given name.
	 *
	 * @param tags the list of tags to inspect
	 * @param name the name to find
	 * @return true if the list contains the tag
	 */
	private boolean containsTag(Collection<FunctionTag> tags, String name) {
		for (FunctionTag tag : tags) {
			if (tag.getName().equals(name)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns a list of all tag names in the given set of function tags.
	 *
	 * @param tags the list of function tags
	 * @return list of tag names
	 */
	private Set<String> getTagNames(Set<FunctionTag> tags) {
		Set<String> tagNames = new HashSet<>();
		for (FunctionTag tag : tags) {
			tagNames.add(tag.getName());
		}

		return tagNames;
	}

	/**
	 * Returns a set of all function tags for the function containing the given address, for the
	 * given listing.
	 *
	 * @param listing the listing
	 * @param addr the function address to inspect
	 * @return set of function tags or an empty set if the address isn't in a function.
	 */
	private Set<FunctionTag> getTagsAtAddress(Listing listing, Address addr) {

		Function function = listing.getFunctionContaining(addr);
		if (function == null) {
			return Collections.emptySet();
		}

		return function.getTags();
	}

	/**
	 * Clears out the function tags at the given address in Result and
	 * replaces them with tags from Origin.
	 *
	 * @param originAddress the function entry point in Origin
	 */
	private void replaceFunctionTags(Address originAddress) {

		Address resultAddress = originToResultTranslator.getAddress(originAddress);

		// Get all the tags in Origin for this function. These are the tags that we'll
		// be keeping.
		Set<FunctionTag> originalTags = getTagsAtAddress(originListing, originAddress);

		// Get the result function and verify it's valid.
		Function resultFunction = resultListing.getFunctionContaining(resultAddress);
		if (resultFunction == null) {
			Msg.error(this, "Error retrieving function at address: " + resultAddress);
			return;
		}

		// Delete all tags in the result. Note the extra step of extracting the tag
		// names and iterating over them to do the remove; we have to do this to avoid
		// a concurrent modification exception.
		Set<FunctionTag> currentResultTags =
			resultListing.getFunctionContaining(resultAddress).getTags();
		Iterator<FunctionTag> iter = currentResultTags.iterator();
		List<String> namesToDelete = new ArrayList<>();
		while (iter.hasNext()) {
			FunctionTag tag = iter.next();
			namesToDelete.add(tag.getName());
		}
		for (String name : namesToDelete) {
			resultFunction.removeTag(name);
		}

		// Add all the tags from Origin into the Result.
		iter = originalTags.iterator();
		while (iter.hasNext()) {
			FunctionTag tag = iter.next();
			resultFunction.addTag(tag.getName());
		}
	}

	// **** SYMBOL methods ****

	/**
	 * <CODE>mergeLabels</CODE> merges all symbols and aliases
	 * in the specified address set from the second program.
	 * It merges them into the merge program.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param setting the current merge label setting.
	 * @param replacePrimary true indicates the primary label should become the same as in the second program.
	 * @param replaceFunction true indicates the function symbol should also be merged.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	void mergeLabels(AddressSetView originAddressSet, int setting, boolean replacePrimary,
			boolean replaceFunction, TaskMonitor monitor) throws CancelledException {
		symbolMerge.mergeLabels(originAddressSet, setting, replacePrimary, replaceFunction,
			conflictSymbolIDMap, monitor);
	}

	/**
	 * <CODE>mergeLabels</CODE> merges all symbols and aliases
	 * in the specified address set from the second program.
	 * It merges them into the merge program.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this address set should be derived from program1.
	 * @param setting the current label setting.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void mergeLabels(AddressSetView originAddressSet, int setting, TaskMonitor monitor)
			throws CancelledException {
		mergeLabels(originAddressSet, setting, true, true, monitor);
	}

	/**
	 * <CODE>replaceLabels</CODE> replaces all symbols and aliases
	 * in the specified address set from the second program.
	 *
	 * @param originAddressSet the addresses to be replaced
	 * The addresses in this address set should be derived from program1.
	 * @param replaceFunction true indicates the function symbol should be replaced
	 * @param monitor the task monitor for notifying the user of this merge's progress
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void replaceLabels(AddressSet originAddressSet, boolean replaceFunction,
			TaskMonitor monitor) throws CancelledException {
		mergeLabels(originAddressSet, ProgramMergeFilter.REPLACE, true, replaceFunction, monitor);
	}

	/**
	 *
	 */
	void reApplyDuplicateSymbols() {
		SymbolTable originSymTab = originProgram.getSymbolTable();
		SymbolTable resultSymTab = resultProgram.getSymbolTable();
		long[] fromSymbolIDs = conflictSymbolIDMap.getKeys();
		for (long fromSymbolID : fromSymbolIDs) {
			try {
				long toSymbolID = conflictSymbolIDMap.get(fromSymbolID);
				Symbol fromSymbol = originSymTab.getSymbol(fromSymbolID);
				Symbol toSymbol = resultSymTab.getSymbol(toSymbolID);
				try {
					toSymbol.setName(fromSymbol.getName(), fromSymbol.getSource());
					conflictSymbolIDMap.remove(fromSymbolID);
				}
				catch (DuplicateNameException e) {
					continue; // Leaves it in the hashtable
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errorMsg.append("InvalidInputException re-applying duplicate symbols: " +
						e.getMessage() + "\n");
				}
			}
			catch (NoValueException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				errorMsg.append(
					"NoValueException re-applying duplicate symbols: " + e.getMessage() + "\n");
			}
		}
	}

	/**
	 *
	 */
	String getDuplicateSymbolsInfo() {
		StringBuffer buf = new StringBuffer();
		SymbolTable origSymTab = originProgram.getSymbolTable();
		SymbolTable resultSymTab = resultProgram.getSymbolTable();
		long[] fromSymbolIDs = conflictSymbolIDMap.getKeys();
		for (long fromSymbolID : fromSymbolIDs) {
			try {
				long toSymbolID = conflictSymbolIDMap.get(fromSymbolID);
				Symbol fromSymbol = origSymTab.getSymbol(fromSymbolID);
				Symbol toSymbol = resultSymTab.getSymbol(toSymbolID);
				String msg = "Symbol '" + fromSymbol.getName(true) + "' renamed to '" +
					toSymbol.getName(true) + "' due to a merge conflict.\n";
				buf.append(msg);
			}
			catch (NoValueException e) {
				Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
				errorMsg.append(
					"NoValueException getting duplicate symbol info: " + e.getMessage() + "\n");
			}
		}
//		Enumeration keys = dupSyms.keys();
//		while (keys.hasMoreElements()) {
//			Symbol sym = (Symbol) keys.nextElement();
//			String desiredName = (String)dupSyms.get(sym);
//			String msg = "Symbol '"+desiredName+"' with '"+sym.getParentNamespace().getName()
//						+"' scope renamed to '"+sym.getName()+"' due to merge conflict.\n";
//			buf.append(msg);
//		}
		return buf.toString();
	}

	/**
	 *
	 */
	void clearDuplicateSymbols() {
		conflictSymbolIDMap.removeAll();
//		dupSyms.clear();
	}

	// **** FUNCTION methods ****

	/**
	 * Determines whether the "fromFunc" function's body overlaps any function bodies that already
	 * exist within the "toProgram" other than a function with an
	 * entry point at the "fromFunc" function's entry point.
	 * @param fromFunc the function whose body should get checked.
	 * @param toProgram the program to check the function body against.
	 * @return true if it overlaps functions other than one with an entry point matching
	 * that of the "fromFunc".
	 */
	static boolean overlapsOtherFunctions(Function fromFunc, Program toProgram) {
		Program fromProgram = fromFunc.getProgram();
		AddressSetView fromBody = fromFunc.getBody();
		AddressSetView newBody = DiffUtility.getCompatibleAddressSet(fromBody, toProgram);
		Address fromEntryPoint = fromFunc.getEntryPoint();
		Address toEntryPoint =
			SimpleDiffUtility.getCompatibleAddress(fromProgram, fromEntryPoint, toProgram);
		FunctionManager toFunctionManager = toProgram.getFunctionManager();
		Iterator<Function> overlapIter = toFunctionManager.getFunctionsOverlapping(newBody);
		while (overlapIter.hasNext()) {
			Function func = overlapIter.next();
			Address overlapEntryPoint = func.getEntryPoint();
			if (!overlapEntryPoint.equals(toEntryPoint)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Determines whether the "fromFunc" function's body overlaps any function bodies that already
	 * exist within the "toProgram" other than a function with an
	 * entry point at the "fromFunc" function's entry point.
	 * @param fromFunc the function whose body should get checked.
	 * @param toProgram the program to check the function body against.
	 * @return true if it overlaps functions other than one with an entry point matching
	 * that of the "fromFunc".
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	static boolean overlapsOtherFunctions(AddressTranslator addressTranslator, Function fromFunc)
			throws UnsupportedOperationException {
		if (!addressTranslator.isOneForOneTranslator()) {
			String message = addressTranslator.getClass().getName() +
				" is not a one for one translator and can't determine function overlap.";
			throw new UnsupportedOperationException(message);
		}
		Program toProgram = addressTranslator.getDestinationProgram();
		AddressSetView fromBody = fromFunc.getBody();
		AddressSetView newBody = addressTranslator.getAddressSet(fromBody);
		Address fromEntryPoint = fromFunc.getEntryPoint();
		Address toEntryPoint = addressTranslator.getAddress(fromEntryPoint);
		FunctionManager toFunctionManager = toProgram.getFunctionManager();
		Iterator<Function> overlapIter = toFunctionManager.getFunctionsOverlapping(newBody);
		while (overlapIter.hasNext()) {
			Function func = overlapIter.next();
			Address overlapEntryPoint = func.getEntryPoint();
			if (!overlapEntryPoint.equals(toEntryPoint)) {
				return true;
			}
		}
		return false;
	}

	/** <CODE>replaceFunctionNames</CODE> merges function name and namespace differences
	 * within the specified address set.
	 *
	 * @param originAddressSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void replaceFunctionNames(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException {

		if (originAddressSet.isEmpty()) {
			return;
		}

		functionMerge.replaceFunctionsNames(originAddressSet, monitor);
	}

	/** <CODE>mergeFunctions</CODE> merges function differences within the specified
	 *  address set.
	 *
	 * @param addrSet the addresses to be merged.
	 * The addresses in this set should be derived from program1.
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public void mergeFunctions(AddressSetView addrSet, TaskMonitor monitor)
			throws CancelledException {

		if (addrSet.isEmpty()) {
			return;
		}

		// Remove functions first to avoid overlap conflicts.
		removeFunctionsNotInProgram2(addrSet, monitor);
		replaceFunctions(addrSet, monitor);
	}

	private void removeFunctionsNotInProgram2(AddressSetView addrSet2, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {
		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't remove functions not in program2.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Removing Functions...");
		AddressSet addrSet1 = originToResultTranslator.getAddressSet(addrSet2);

		FunctionManager funcMgr1 = this.resultProgram.getFunctionManager();
		FunctionManager funcMgr2 = this.originProgram.getFunctionManager();
		FunctionIterator funcIter1 = funcMgr1.getFunctions(addrSet1, true);
		FunctionIterator funcIter2 = funcMgr2.getFunctions(addrSet2, true);
		FunctionAddressIterator iter1 = new FunctionAddressIterator(funcIter1);
		FunctionAddressIterator iter2 = new FunctionAddressIterator(funcIter2);

		HashSet<Address> resultsToKeep = new HashSet<>();
		while (iter2.hasNext()) {
			monitor.checkCanceled();
			Address addr2 = iter2.next();
			Address addr1 = originToResultTranslator.getAddress(addr2);
			resultsToKeep.add(addr1);
		}
		while (iter1.hasNext()) {
			monitor.checkCanceled();
			Address resultAddress = iter1.next();
			if (!resultsToKeep.contains(resultAddress)) {
				monitor.setMessage("Removing Functions...   " + resultAddress.toString(true));
				funcMgr1.removeFunction(resultAddress);
			}
		}
	}

	private void replaceFunctions(AddressSetView addrSet2, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {
		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't replace functions.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Replacing Functions...");
		AddressSet addrSet = originToResultTranslator.getAddressSet(addrSet2);

		FunctionManager resultFM = resultProgram.getFunctionManager();
		FunctionManager originFM = originProgram.getFunctionManager();
		FunctionIterator funcIter1 = resultFM.getFunctions(addrSet, true);
		FunctionIterator funcIter2 = originFM.getFunctions(addrSet2, true);
		FunctionAddressIterator iter1 = new FunctionAddressIterator(funcIter1);
		FunctionAddressIterator iter2 = new FunctionAddressIterator(funcIter2);
		AddressIteratorConverter convertedIter2 =
			new AddressIteratorConverter(originProgram, iter2, resultProgram);
		// Get the addresses in the set.
		MultiAddressIterator functionIter =
			new MultiAddressIterator(new AddressIterator[] { iter1, convertedIter2 });
		AddressSet resultEntrySet = new AddressSet();
		while (functionIter.hasNext()) {
			monitor.checkCanceled();
			Address address = functionIter.next();
			resultEntrySet.addRange(address, address);
		}
		// Get each address in the address set and change the function.
		long totalAddresses = resultEntrySet.getNumAddresses();
		long granularity = (totalAddresses / PROGRESS_COUNTER_GRANULARITY) + 1;
		monitor.initialize(totalAddresses);
		AddressSet thunkSet = new AddressSet();
		AddressIterator it = resultEntrySet.getAddresses(true);
		for (int count = 0; it.hasNext(); count++) {
			monitor.checkCanceled();
			Address address = it.next();
			if (count % granularity == 0) {
				monitor.setProgress(count);
				monitor.setMessage("Replacing Function " + (count + 1) + " of " + totalAddresses +
					"." + " Address = " + address.toString(true));
			}
			if (isThunkFunction(address)) {
				// Skip the thunk, but save it for processing during a second pass.
				thunkSet.addRange(address, address);
				continue;
			}
			replaceFunction(address, monitor);
		}
		monitor.setProgress(totalAddresses);

		replaceThunks(thunkSet, monitor);
	}

	private void replaceThunks(AddressSet thunkSet, TaskMonitor monitor) throws CancelledException {
		long granularity;
		// Now that all the non-thunk functions have been processed, process the saved thunks.
		long totalThunks = thunkSet.getNumAddresses();
		granularity = (totalThunks / PROGRESS_COUNTER_GRANULARITY) + 1;
		monitor.initialize(totalThunks);
		AddressIterator thunkIter = thunkSet.getAddresses(true);
		for (int count = 0; thunkIter.hasNext(); count++) {
			monitor.checkCanceled();
			Address address = thunkIter.next();
			if (count % granularity == 0) {
				monitor.setProgress(count);
				monitor.setMessage("Replacing Thunk Function " + (count + 1) + " of " +
					totalThunks + "." + " Address = " + address.toString(true));
			}
			replaceFunction(address, monitor);
		}
		monitor.setProgress(totalThunks);
	}

	private boolean isThunkFunction(Address originEntryPoint) {
		Function originFunction = originListing.getFunctionAt(originEntryPoint);
		if (originFunction != null && originFunction.isThunk()) {
			return true;
		}
		return false;
	}

	class FunctionAddressIterator implements AddressIterator {
		FunctionIterator functionIterator;

		FunctionAddressIterator(FunctionIterator funcIter) {
			this.functionIterator = funcIter;
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.address.AddressIterator#next()
		 */
		@Override
		public Address next() {
			return functionIterator.next().getEntryPoint();
		}

		/* (non-Javadoc)
		 * @see ghidra.program.model.address.AddressIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			return functionIterator.hasNext();
		}

		/**
		 * @see java.util.Iterator#remove()
		 */
		@Override
		public void remove() {
			throw new UnsupportedOperationException();
		}

		@Override
		public Iterator<Address> iterator() {
			return this;
		}
	}

	/**
	 * <CODE>mergeFunction</CODE> completely replaces any function at the
	 * indicated address in program1 with the function, if any, in program2.
	 *
	 * @param entry the entry point address of the function to be merged.
	 * This address should be derived from program1.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	public Function mergeFunction(Address entry, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();
//        monitor.setMessage("Replacing Function...   " + address.toString(true));
		return replaceFunction(entry, monitor);
	}

	/**
	 * <CODE>mergeFunctionReturn</CODE> replaces the return type/storage of the
	 * function in program1 with the return type/storage of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 */
	public void mergeFunctionReturn(Address entry2) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			try {
				Parameter f1Return = f1.getReturn();
				Parameter f2Return = f2.getReturn();
				DataType dt1 = f1Return.getDataType();
				DataType dt2 = f2Return.getDataType();
				boolean storageMatches =
					f1Return.getVariableStorage().equals(f2Return.getVariableStorage());
				if (sameDataType(dt1, dt2)) {
					if (storageMatches) {
						return;
					}
					dt2 = dt1;
				}
				else if (storageMatches) {
					if (!f1.hasCustomVariableStorage()) {
						dt2 = f2Return.getFormalDataType();
					}
					f1Return.setDataType(dt2, f2.getSignatureSource());
					return;
				}
				try {
					// assume return storage does not match between f1 and f2
					if (f2.hasCustomVariableStorage()) {
						f1.setCustomVariableStorage(true); //
					}
					else if (!f1.hasCustomVariableStorage()) {
						dt2 = f2Return.getFormalDataType(); // allow dynamic storage to handle use of return storage pointer
					}
					f1Return.setDataType(dt2, f2Return.getVariableStorage(), true,
						f2.getSignatureSource());
				}
				catch (InvalidInputException e) {
					f1Return.setDataType(dt2, VariableStorage.UNASSIGNED_STORAGE, false,
						SourceType.DEFAULT);
					String msg = "Return storage forced to UNASSIGNED for " + f1.getName(true) +
						":\n    " + e.getMessage();
					Msg.error(this, msg);
					errorMsg.append(msg + "\n");
				}
			}
			catch (InvalidInputException e) {
				errorMsg.append("Failed to replace function return for " + f1.getName() + ": " +
					e.getMessage());
			}
		}
	}

	/**
	 * <CODE>replaceExternalDataType</CODE> replaces the data type of the
	 * external label in program1 with the data type of the external label in program2
	 * at the specified external space address.
	 * @param originAddress external space address the address of the external.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException
	 */
	// FIXME
//	public void replaceExternalDataType(Address originAddress, TaskMonitor monitor)
//			throws CancelledException {
//		monitor.checkCanceled();
//		Address resultAddress = originToResultTranslator.getAddress(originAddress);
//		Symbol originSymbol = originProgram.getSymbolTable().getPrimarySymbol(originAddress);
//		Symbol resultSymbol = resultProgram.getSymbolTable().getPrimarySymbol(resultAddress);
//		ExternalLocation originExternalLocation =
//			originProgram.getExternalManager().getExternalLocation(originSymbol);
//		ExternalLocation resultExternalLocation =
//			resultProgram.getExternalManager().getExternalLocation(resultSymbol);
//		if (originExternalLocation != null && resultExternalLocation != null) {
//			DataType originDataType = originExternalLocation.getDataType();
//			DataType resultDataType = resultExternalLocation.getDataType();
//			if (sameDataType(originDataType, resultDataType)) {
//				return; // Already the same.
//			}
//			resultExternalLocation.setDataType(originDataType);
//		}
//	}

	/**
	 * <CODE>mergeFunctionName</CODE> replaces the name of the
	 * function in program1 with the name of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void mergeFunctionName(Address entry2, TaskMonitor monitor) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			replaceFunctionName(f1, f2.getName(), f2.getSymbol().getSource());
		}
	}

	private boolean replaceFunctionName(Function function, String name, SourceType source) {
		if (function != null) {
			Address entry = function.getEntryPoint();
			String origName = function.getName();
			if (!SystemUtilities.isEqual(origName, name)) {
				for (int i = 0; i < Integer.MAX_VALUE; i++) {
					String newName =
						(i == 0) ? name : name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
					try {
						function.setName(newName, source);
						if (i > 0) {
							infoMsg.append("Function '" + name + "' was merged as '" + newName +
								"' @ address " + entry.toString() + ".\n");
						}
						return true;
					}
					catch (DuplicateNameException e) {
						continue;
					}
					catch (InvalidInputException e) {
						errorMsg.append(
							"Address = " + entry.toString() + ": " + e.getMessage() + "\n");
						return false;
					}
				}
				errorMsg.append("Function '" + origName + "' couldn't be renamed to '" + name +
					"' @ address " + entry.toString() + ".\n");
				return false;
			}
		}
		return false;
	}

	private boolean sameDataType(DataType dt1, DataType dt2) {
		return (dt1 == null) ? (dt2 == null) : (dt1.isEquivalent(dt2));
	}

	/**
	 * <CODE>replaceFunctionSignatureSource</CODE> changes the result function's signature source
	 * to match the origin program's signature source.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionSignatureSource(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function resultFunction =
			resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function originFunction =
			originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (resultFunction != null && originFunction != null) {
			SourceType resultSignatureSource = resultFunction.getSignatureSource();
			SourceType originSignatureSource = originFunction.getSignatureSource();
			if (resultSignatureSource != originSignatureSource) {
				resultFunction.setSignatureSource(originSignatureSource);
			}
		}
	}

	/**
	 * <CODE>mergeFunctionReturnAddressOffset</CODE> replaces the return address offset of the
	 * function in program1 with the return address offset of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void mergeFunctionReturnAddressOffset(Address entry2, TaskMonitor monitor) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			StackFrame sf1 = f1.getStackFrame();
			StackFrame sf2 = f2.getStackFrame();
			int off1 = sf1.getReturnAddressOffset();
			int off2 = sf2.getReturnAddressOffset();
			if (off1 != off2) {
				sf1.setReturnAddressOffset(off2);
			}
		}
	}

	/**
	 * <CODE>mergeFunctionParameterOffset</CODE> replaces the parameter offset of the
	 * function in program1 with the parameter offset of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
//	public void mergeFunctionParameterOffset(Address entry2, TaskMonitor monitor) {
//		Address entry = originToResultTranslator.getAddress(entry2);
//		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
//		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
//		if (f1 != null && f2 != null) {
//			StackFrame sf1 = f1.getStackFrame();
//			StackFrame sf2 = f2.getStackFrame();
//			int po1 = sf1.getParameterOffset();
//			int po2 = sf2.getParameterOffset();
//			if (po1 != po2) {
//				try {
//					sf1.setParameterOffset(po2);
//				}
//				catch (InvalidInputException e) {
//					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
//					errorMsg.append("InvalidInputException setting function parameter offset: " +
//							e.getMessage() + "\n");
//				}
//			}
//		}
//	}

	/**
	 * <CODE>mergeFunctionLocalSize</CODE> replaces the local size of the
	 * function in program1 with the local size of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void mergeFunctionLocalSize(Address entry2, TaskMonitor monitor) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			StackFrame sf1 = f1.getStackFrame();
			StackFrame sf2 = f2.getStackFrame();
			int ls1 = sf1.getLocalSize();
			int ls2 = sf2.getLocalSize();
			if (ls1 != ls2) {
				sf1.setLocalSize(ls2);
			}
		}
	}

	/**
	 * <CODE>mergeFunctionStackPurgeSize</CODE> replaces the stack purge size of the
	 * function in program1 with the stack purge size of the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void mergeFunctionStackPurgeSize(Address entry2, TaskMonitor monitor) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			int sp1 = f1.getStackPurgeSize();
			int sp2 = f2.getStackPurgeSize();
			if (sp1 != sp2) {
				f1.setStackPurgeSize(f2.getStackPurgeSize());
			}
		}
	}

	/**
	 * <CODE>replaceFunctionVarArgs</CODE> changes whether the function has VarArgs
	 * in program1 if it doesn't match the use of VarArgs in the function in program2
	 * at the specified entry point address.
	 * @param entry2 the entry point address of the function.
	 * This address should be derived from program1.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionVarArgs(Address entry2, TaskMonitor monitor) {
		Address entry = originToResultTranslator.getAddress(entry2);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(entry);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(entry2);
		if (f1 != null && f2 != null) {
			boolean hasVarArgs1 = f1.hasVarArgs();
			boolean hasVarArgs2 = f2.hasVarArgs();
			if (hasVarArgs1 != hasVarArgs2) {
				f1.setVarArgs(hasVarArgs2);
			}
		}
	}

	/**
	 * <CODE>replaceFunctionCallingConvention</CODE> changes the function calling convention
	 * in program1 if it doesn't match the function calling convention in program2
	 * at the specified entry point address.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionCallingConvention(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			String name1 = f1.getCallingConventionName();
			String name2 = f2.getCallingConventionName();
			if (!name1.equals(name2)) {
				try {
					f1.setCallingConvention(name2);
				}
				catch (InvalidInputException e) {
					errorMsg.append("InvalidInputException replacing calling convention: " +
						e.getMessage() + "\n");
				}
			}
		}
	}

	/**
	 * <CODE>replaceFunctionInlineFlag</CODE> changes whether the function is inline
	 * in program1 if it doesn't match whether the function is inline in program2
	 * at the specified entry point address.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionInlineFlag(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			boolean isInline1 = f1.isInline();
			boolean isInline2 = f2.isInline();
			if (isInline1 != isInline2) {
				f1.setInline(isInline2);
			}
		}
	}

	/**
	 * <CODE>replaceFunctionNoReturnFlag</CODE> changes whether the flag is set indicating
	 * the function does not return
	 * in program1 if it doesn't match the "does not return" flag in the function in program2
	 * at the specified entry point address.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionNoReturnFlag(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			boolean hasNoReturn1 = f1.hasNoReturn();
			boolean hasNoReturn2 = f2.hasNoReturn();
			if (hasNoReturn1 != hasNoReturn2) {
				f1.setNoReturn(hasNoReturn2);
			}
		}
	}

	/**
	 * <CODE>replaceFunctionCustomStorageFlag</CODE> changes whether the flag is set indicating
	 * the function does not return
	 * in program1 if it doesn't match the "custom storage" flag in the function in program2
	 * at the specified entry point address.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 */
	public void replaceFunctionCustomStorageFlag(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			boolean hasCustomStorage1 = f1.hasCustomVariableStorage();
			boolean hasCustomStorage2 = f2.hasCustomVariableStorage();
			if (hasCustomStorage1 != hasCustomStorage2) {
				f1.setCustomVariableStorage(hasCustomStorage2);
			}
		}
	}

	/**
	 * <CODE>replaceFunctionParameters</CODE> replaces the parameters of the
	 * function in program1 with the parameters of the function in program2
	 * at the specified entry point address.  It also replaces the return
	 * type/storage as well as custom storage use.
	 * @param originEntryPoint the entry point address of the function.
	 * This address should be derived from the origin program.
	 */
	public void replaceFunctionParameters(Address originEntryPoint, TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function resultFunction =
			resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function originFunction =
			originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		replaceFunctionParameters(resultFunction, originFunction);
	}

	/**
	 * <CODE>replaceFunctionParameters</CODE> replaces the parameters of the
	 * function in program1 with the parameters of the function in program2
	 * at the specified entry point address.  It also replaces the return
	 * type/storage as well as custom storage use.
	 * @param toFunc target function
	 * @param fromFunc source function
	 */
	public void replaceFunctionParameters(Function toFunc, Function fromFunc) {

		if (toFunc == null || fromFunc == null) {
			return;
		}

		try {

			Parameter[] fromParams = fromFunc.getParameters();
			if (!resolveParamaterNameConflicts(toFunc, fromParams)) {
				return;
			}

			toFunc.updateFunction(toFunc.getCallingConventionName(), fromFunc.getReturn(),
				fromFunc.hasCustomVariableStorage() ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, fromFunc.getSignatureSource(), fromParams);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append("Can't replace parameters for function " + toFunc.getName(true));
			errorMsg.append(e.getMessage() + "\n");
			return;
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append("Can't replace return/parameters for function " + toFunc.getName(true));
			errorMsg.append(e.getMessage() + "\n");
			return;
		}

		// Add or remove the varargs as necessary.
		boolean shouldHaveVarArgs = fromFunc.hasVarArgs();
		if (toFunc.hasVarArgs() != shouldHaveVarArgs) {
			toFunc.setVarArgs(shouldHaveVarArgs);
		}

	}

	/**
	 * Create a name that is unique in both namespaces of the given symbolTable.
	 *
	 * @param symbolTable the symbolTable where the symbol will be created.
	 * @param name the desired name. This name will be given a conflict suffix if necessary
	 * to make it unique.
	 * @param address the address of the symbol.
	 * @param namespace1 the first namespace where the new symbol should be unique. 
	 * This namespace must be from the same program as the symbol table.
	 * @param namespace2 the second namespace where the new symbol should be unique.
	 * This namespace must be from the same program as the symbol table.
	 * @param type the symbol type of the symbol.
	 * @return a unique name for both namespaces.
	 */
	public static String getUniqueName(SymbolTable symbolTable, String name, Address address,
			Namespace namespace1, Namespace namespace2, SymbolType type) {

		String newName = name;
		int i = 1;
		for (; i < Integer.MAX_VALUE; i++) {
			boolean canCreateSymbol1 =
				isUniqueSymbolName(symbolTable, namespace1, newName, address, type);
			boolean canCreateSymbol2 =
				isUniqueSymbolName(symbolTable, namespace2, newName, address, type);

			if (canCreateSymbol1 && canCreateSymbol2) {
				return newName;
			}
			newName = name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
		}
		throw new AssertException("This is crazy!");
	}

	/**
	 * Create a name that is unique in the indicated namespace of the symbol table.
	 *
	 * @param symbolTable the symbolTable where the symbol will be created.
	 * @param name the desired name. This name will be given a conflict suffix if necessary
	 * to make it unique.
	 * @param address the address of the symbol.
	 * @param namespace the namespace where the new symbol would be created.
	 * This namespace must be from the same program as the symbol table.
	 * @param type the type of symbol.
	 * @return a unique name within the namespace.
	 */
	public static String getUniqueName(SymbolTable symbolTable, String name, Address address,
			Namespace namespace, SymbolType type) {

		String newName = name;
		int i = 1;
		for (; i < Integer.MAX_VALUE; i++) {
			boolean canCreateSymbol =
				isUniqueSymbolName(symbolTable, namespace, newName, address, type);

			if (canCreateSymbol) {
				return newName;
			}
			newName = name + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
		}
		throw new AssertException("Couldn't get a unique symbol name for " + name);
	}

	/**
	 * Tests if a symbol can successfully be created.  This is useful when creating symbol
	 * types that require unique names such as Namespaces, Libraries, and Classes.
	 * @param namespace the namespace where the new symbol would be created.
	 * @param name the name of the symbol to test.
	 * @param address the address of the symbol to test. (Can be null)
	 * @param type the symbol type of the symbol to test.
	 * @return true if the symbol with the given properties could be created without causing
	 * a duplicate name exception.
	 */
	private static boolean isUniqueSymbolName(SymbolTable symbolTable, Namespace namespace,
			String name, Address address, SymbolType type) {

		if (address.isExternalAddress()) {
			return false;
		}

		if (symbolTable.getSymbol(name, address, namespace) != null) {
			return false;
		}
		if (type.allowsDuplicates()) {
			return true;
		}
		List<Symbol> symbols = symbolTable.getSymbols(name, namespace);
		for (Symbol symbol : symbols) {
			if (!symbol.getSymbolType().allowsDuplicates()) {
				return false;
			}
		}
		return true;
	}

	/** Adds/Replaces/Removes a function at the specified address in the
	 * resultListing based on the function in the origListing.
	 * <br>Note: This method will replace the function, but does not create
	 * the parent namespace or put the function in the parent namespace.
	 * This must be done separately.
	 * @param originEntryPoint the address of the functions entry point.
	 * This address should be derived from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @return the new function that was created in the resultListing or null
	 * if no function was created. If null is returned you should call
	 * getErrorMessage() to see if an error occurred.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	private Function replaceFunction(Address originEntryPoint, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {
		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't replace a function.";
			throw new UnsupportedOperationException(message);
		}
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function originFunction = originListing.getFunctionAt(originEntryPoint);
		Function resultFunction = resultListing.getFunctionAt(resultEntryPoint);
		// Check for removing function or no function
		if (originFunction == null) {
			if (resultFunction != null) {
				resultListing.removeFunction(resultEntryPoint); // remove the original function
			}
			return null;
		}
		if (ProgramDiff.equivalentFunctions(originFunction, resultFunction, false)) {
			return resultFunction;
		}

		boolean isDefaultThunk = false;
		if (originFunction.isThunk()) {
			isDefaultThunk = originFunction.getSymbol().getSource() == SourceType.DEFAULT;
			Function thunkedFunction = originFunction.getThunkedFunction(false);
			Address thunkedEntryPoint = thunkedFunction.getEntryPoint();
			Address resultThunkedEntryPoint =
				originToResultTranslator.getAddress(thunkedEntryPoint);
			if (resultThunkedEntryPoint == null) {
				errorMsg.append("Can't replace thunk function @ " + originEntryPoint + ". " +
					"Can't determine equivalent thunked function entry point address " +
					"for thunked function @ " + thunkedEntryPoint + ".\n");
				return null;
			}
			Function resultThunkedFunction = resultListing.getFunctionAt(resultThunkedEntryPoint);
			if (resultThunkedFunction == null) {
				errorMsg.append("Can't replace thunk function @ " + originEntryPoint +
					". No function at pointed to address " + thunkedEntryPoint + ".\n");
				return null;
			}
		}

		Function newResultFunction = resultFunction; // initially assume the body hasn't changed.
		AddressSetView originBody = originFunction.getBody();
		AddressSet newResultBody = originToResultTranslator.getAddressSet(originBody);

		// Check for function body overlap conflict.
		if (ProgramMerge.overlapsOtherFunctions(originToResultTranslator, originFunction)) {
			errorMsg.append("Can't replace function @ " + originEntryPoint +
				". It would overlap another function.\n");
			return null;
		}

//        VariableReference[] restoreRefs = new VariableReference[0];
		String originName = originFunction.getName();
		Namespace desiredToNamespace = resultProgram.getGlobalNamespace();
		if (!isDefaultThunk) {
			try {
				desiredToNamespace = symbolMerge
						.resolveNamespace(originFunction.getParentNamespace(), conflictSymbolIDMap);
			}
			catch (DuplicateNameException e1) {
				Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
			}
			catch (InvalidInputException e1) {
				Msg.error(this, "Unexpected Exception: " + e1.getMessage(), e1);
			}
		}

		AddressSetView oldResultBody = (resultFunction == null) ? null : resultFunction.getBody();
		boolean sameBody = newResultBody.equals(oldResultBody);
		if (!sameBody) {
			try {
				// Changing function?
				if (resultFunction != null) {
					resultFunction.setBody(newResultBody);
				}
				else {
					try {
						newResultFunction = resultListing.createFunction(originName,
							desiredToNamespace, originEntryPoint, newResultBody,
							originFunction.getSymbol().getSource());
					}
					catch (InvalidInputException e) {
						String errorMessage = "Error creating function \"" + originName + "\" at " +
							originEntryPoint.toString(true) + ".\n  ";
						errorMsg.append(errorMessage + e.getMessage());
						return null;
					}
					/* createFunction appears to throw an IllegalArgumentException
					 * if data exists where you are trying to create the function.
					 * This should really happen via the InvalidInputException above.
					 */
					catch (IllegalArgumentException e) {
						String errorMessage = "Error creating function \"" + originName + "\" at " +
							originEntryPoint.toString(true) + ".\n  ";
						errorMsg.append(errorMessage + e.getMessage());
						return null;
					}
				}
			}
			catch (OverlappingFunctionException e) {
				errorMsg.append("Address = " + resultEntryPoint + ": " + e.getMessage() + "\n");
				return null;
			}
		}
		if (newResultFunction == null) {
			return null;
		}

		// Handle thunk
		if (originFunction.isThunk()) {
			Function originThunkedFunction = originFunction.getThunkedFunction(false);
			Function originThunkedFunctionInResult =
				DiffUtility.getFunction(originThunkedFunction, resultProgram);
			if (originThunkedFunctionInResult == null) {
				// No matching function to thunk to.
				errorMsg.append(
					"Thunked function not found at " + originThunkedFunction.getEntryPoint() +
						" for function at " + originFunction.getEntryPoint() + ".\n");
				return null;
			}
			Function currentThunkedFunction = newResultFunction.getThunkedFunction(false);
			if (currentThunkedFunction != originThunkedFunctionInResult) {
				newResultFunction.setThunkedFunction(originThunkedFunctionInResult);
			}
		}
		else if (newResultFunction.isThunk()) {
			newResultFunction.setThunkedFunction(null);
		}

		if (newResultFunction.isThunk()) {
			// A thunk Function has its own name and body but refers to another function,
			// so we don't want to affect the return type, calling convention, variables, etc.
			// Body was handled above and the name will get handled later.
			return newResultFunction;
		}

		// Do not replace the function name here, since the symbols need to get sorted out first.
		// After the symbols are merged you will need to replace the function symbol in case the
		// merge of symbols was not chosen.
		try {
			newResultFunction.updateFunction(originFunction.getCallingConventionName(),
				originFunction.getReturn(),
				originFunction.hasCustomVariableStorage() ? FunctionUpdateType.CUSTOM_STORAGE
						: FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
				true, originFunction.getSignatureSource(), originFunction.getParameters());
		}
		catch (DuplicateNameException e) {
			// should not occur
			errorMsg.append("Address = " + resultEntryPoint + ": " + e.getMessage() + "\n");
		}
		catch (InvalidInputException e) {
			errorMsg.append("Address = " + resultEntryPoint + ": " + e.getMessage() + "\n");
		}

		StackFrame originFrame = originFunction.getStackFrame();
		StackFrame newToFrame = newResultFunction.getStackFrame();
		newToFrame.setLocalSize(originFrame.getLocalSize());
		newToFrame.setReturnAddressOffset(originFrame.getReturnAddressOffset());

		newResultFunction.setStackPurgeSize(originFunction.getStackPurgeSize());
		newResultFunction.setVarArgs(originFunction.hasVarArgs());
		newResultFunction.setInline(originFunction.isInline());
		newResultFunction.setNoReturn(originFunction.hasNoReturn());

		replaceLocals(newResultFunction, originFunction, monitor);

//		restoreVariableRefs(newResultFunction, restoreRefs);

		newResultFunction.setSignatureSource(originFunction.getSignatureSource());

		return newResultFunction;
	}

	/** Replaces the external result function with the origin Function.
	 * <br>Note: This method will replace the function, but does not create
	 * the parent namespace or put the function in the parent namespace.
	 * This must be done separately.
	 * @param toFunction the result function to replace.
	 * @param fromFunction the function to use as the model when replacing the result function.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @return the new function that was created in the resultListing or null
	 * if no function was created. If null is returned you should call
	 * getErrorMessage() to see if an error occurred.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translators are not
	 * "one for one translators".
	 */
	public Function replaceExternalFunction(Function toFunction, Function fromFunction,
			TaskMonitor monitor) throws CancelledException, UnsupportedOperationException {

		if (!toFunction.isExternal()) {
			throw new IllegalArgumentException("The function being replaced is not an external.");
		}
		if (!fromFunction.isExternal()) {
			throw new IllegalArgumentException(
				"The function being used as the source of information for a replace is not an external.");
		}

		StackFrame originFrame = fromFunction.getStackFrame();

		// Do not replace the function name here, since the symbols need to get sorted out first.
		// After the symbols are merged you will need to replace the function symbol in case the
		// merge of symbols was not chosen.

		if (toFunction.hasCustomVariableStorage() != fromFunction.hasCustomVariableStorage()) {
			toFunction.setCustomVariableStorage(fromFunction.hasCustomVariableStorage());
		}

		try {
			toFunction.setCallingConvention(fromFunction.getCallingConventionName());
		}
		catch (InvalidInputException e) {
			errorMsg.append(
				"Address = " + toFunction.getEntryPoint() + ": " + e.getMessage() + "\n");
		}
		StackFrame newToFrame = toFunction.getStackFrame();
		try {
			if (toFunction.hasCustomVariableStorage()) {
				Variable returnVar = fromFunction.getReturn();
				toFunction.setReturn(fromFunction.getReturnType(), returnVar.getVariableStorage(),
					returnVar.getSource());
			}
			else {
				toFunction.setReturnType(fromFunction.getReturnType(), SourceType.ANALYSIS);
			}
//			if (newToFrame.getParameterOffset() != originFrame.getParameterOffset()) {
//				newToFrame.setParameterOffset(originFrame.getParameterOffset());
//			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append(
				"InvalidInputException replacing external function: " + e.getMessage() + "\n");
		}

		if (newToFrame.getLocalSize() != originFrame.getLocalSize()) {
			newToFrame.setLocalSize(originFrame.getLocalSize());
		}

		toFunction.setStackPurgeSize(fromFunction.getStackPurgeSize());

		toFunction.setVarArgs(fromFunction.hasVarArgs());
		toFunction.setInline(fromFunction.isInline());
		toFunction.setNoReturn(fromFunction.hasNoReturn());
		toFunction.setSignatureSource(fromFunction.getSignatureSource());
		replaceVariables(toFunction, fromFunction, monitor);
//		restoreVariableRefs(newResultFunction, restoreRefs);

		return toFunction;
	}

	/**
	 * @param newFunc
	 * @param fromFunc
	 * @throws CancelledException if user cancels via the monitor.
	 */
	private void replaceVariables(Function newFunc, Function fromFunc, TaskMonitor monitor)
			throws CancelledException {
		replaceFunctionParameters(newFunc, fromFunc);
		replaceLocals(newFunc, fromFunc, monitor);
	}

	private boolean resolveParamaterNameConflicts(Function toFunc, Parameter[] fromParams) {
		for (Parameter p : fromParams) {
			if (p.getSource() != SourceType.DEFAULT &&
				!resolveParameterNameConflict(toFunc, p.getName())) {
				return false;
			}
		}
		return true;
	}

	private boolean resolveParameterNameConflict(Function toFunc, String name) {
		SymbolTable toSymTab = toFunc.getProgram().getSymbolTable();
		Symbol nameSpaceSymbol = toSymTab.getLocalVariableSymbol(name, toFunc); // Another symbol with the same name in the namespace.
		if (nameSpaceSymbol != null && nameSpaceSymbol.getSymbolType() != SymbolType.PARAMETER &&
			nameSpaceSymbol.getSource() != SourceType.DEFAULT) {
			// If we run into the name already in toFunc on a different variable
			// then temp rename it so we can proceed.
			if (renameVarUniquely(nameSpaceSymbol, nameSpaceSymbol.getSource()) == null) {
				errorMsg.append("Can't replace parameters due to name conflict: " +
					nameSpaceSymbol.getName(true) + "\n");
				return false;
			}
			String msg = "Renamed symbol '" + name + "' in function '" + toFunc.getName() +
				"' to '" + nameSpaceSymbol.getName() + "' due to conflict with parameter.\n";
			infoMsg.append(msg);
		}
		return true;
	}

	/**
	 * Replaces the local symbols in toFunc with the local symbols that are in the fromFunc.
	 * @param toFunc the function having its local variables replaced.
	 * @param fromFunc the source of the replacement variables.
	 * @throws CancelledException if user cancels via the monitor.
	 */
	private void replaceLocals(Function toFunc, Function fromFunc, TaskMonitor monitor)
			throws CancelledException {
		Variable[] oldLocals = toFunc.getLocalVariables();
		Variable[] fromLocals = fromFunc.getLocalVariables();
		if (Arrays.equals(oldLocals, fromLocals)) {
			return;
		}
		// Remove all locals in the toFunc that don't have a comparable local in the fromFunc.
		for (Variable local : oldLocals) {
			monitor.checkCanceled();
			Variable fromVar = DiffUtility.getVariable(local, fromFunc);
			if (fromVar == null) {
				toFunc.removeVariable(local);
			}
		}
		for (Variable fromLocal : fromLocals) {
			monitor.checkCanceled();
			replaceVariable(fromFunc, fromLocal, toFunc);
		}
	}

	private Variable replaceVariable(Function fromFunc, Variable fromVar, Function toFunc) {
		if (fromVar instanceof Parameter) {
			throw new IllegalArgumentException("replaceVariable should not be used for parameters");
		}
		Program toPgm = toFunc.getProgram();
		Program fromPgm = fromFunc.getProgram();
		String name = fromVar.getName();
		SourceType source = fromVar.getSource();
		Variable toVar = DiffUtility.getVariable(fromVar, toFunc); // requires matching storage and first-use
		if (toVar == null) {
			try {
				VariableUtilities.checkVariableConflict(toFunc, fromVar,
					fromVar.getVariableStorage(), true);
			}
			catch (VariableSizeException e) {
				throw new RuntimeException("Unexpected Exception", e);
			}
		}
		else if (toVar.equals(fromVar)) {
			return toVar;
		}
		if (fromVar.getSource() != SourceType.DEFAULT &&
			(toVar == null || !toVar.getName().equals(fromVar.getName()))) {
			if (!resolveLocalNameConflict(toFunc, fromVar.getName())) {
				return null; // Error case
			}
		}
		try {
//			if (toVar != null && !DiffUtility.variableStorageMatches(fromVar, toVar)) {
//				// if variable size does not match - play it safe and don't try to fix-up toVar
//				toVar.getFunction().removeVariable(toVar);
//				toVar = null;
//			}
			if (toVar != null) {
				// update existing variable - preserve symbol ID
				toVar.setComment(fromVar.getComment());
				DataType fromDt = fromVar.getDataType();
				if (!fromDt.isEquivalent(toVar.getDataType())) {
					toVar.setDataType(fromDt, fromVar.getVariableStorage(), true,
						fromFunc.getSignatureSource());
				}
				toVar.setName(name, source);
			}
			else {
				toVar = DiffUtility.createVariable(fromPgm, fromVar, toPgm);
			}
		}
		catch (InvalidInputException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append("Can't replace variable " + fromVar.getSymbol().getName(true) + "\n");
			errorMsg.append(e.getMessage() + "\n");
			return null;
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
			errorMsg.append("Can't replace variable " + fromVar.getSymbol().getName(true) + "\n");
			errorMsg.append(e.getMessage() + "\n");
			return null;
		}
		return toVar;
	}

	private boolean resolveLocalNameConflict(Function toFunc, String name) {
		SymbolTable toSymTab = toFunc.getProgram().getSymbolTable();
		Symbol nameSpaceSymbol = toSymTab.getVariableSymbol(name, toFunc); // Another symbol with the same name in the namespace.
		if (nameSpaceSymbol != null && nameSpaceSymbol.getSource() != SourceType.DEFAULT) {
			// If we run into the name already in toFunc on a different variable
			// then temp rename it so we can proceed.
			if (renameVarUniquely(nameSpaceSymbol, nameSpaceSymbol.getSource()) == null) {
				errorMsg.append("Can't replace variable due to name conflict: " +
					nameSpaceSymbol.getName(true) + "\n");
				return false;
			}
			String msg = "Renamed symbol '" + name + "' in function '" + toFunc.getName() +
				"' to '" + nameSpaceSymbol.getName() + "' due to conflict with local variable.\n";
			infoMsg.append(msg);
		}
		return true;
	}

	/**
	 * Changes the variable's name to a unique name.
	 * @param namedSymbol the variable's symbol
	 * @param source the source of this variable's symbol
	 * @return the new name or null if it couldn't be renamed.
	 */
	private String renameVarUniquely(Symbol namedSymbol, SourceType source) {
		String name = namedSymbol.getName();
		for (int i = 1; i < Integer.MAX_VALUE; i++) {
			String newName = name + SYMBOL_CONFLICT_SUFFIX + i;
			try {
				namedSymbol.setName(newName, namedSymbol.getSource());
				return newName;
			}
			catch (DuplicateNameException e) {
				continue;
			}
			catch (InvalidInputException e) {
				break;
			}
		}
		return null;
	}

//	/**
//	 * <CODE>replaceFunctionParameter</CODE> replaces the indicated parameter
//	 * in program1 with that in program2 for the function with the specified entry point.
//	 * @param originEntryPoint the entry point address of the function to modify.
//	 * This address should be derived from the origin program.
//	 * @param ordinal the index of the parameter to replace.
//	 * @param monitor the task monitor for notifying the user of progress.
//	 * @return the new parameter or null if it couldn't be replaced.
//	 * @throws DuplicateNameException
//	 */
//	public Parameter replaceFunctionParameter(Address originEntryPoint, int ordinal,
//			TaskMonitor monitor) {
//		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
//		Function resultFunction =
//			resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
//		Function originFunction =
//			originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
//		Parameter originParam = originFunction.getParameter(ordinal);
//		if (originParam != null) {
//			return (Parameter) replaceVariable(originFunction, originParam, resultFunction);
//		}
//		resultFunction.removeParameter(ordinal);
//		return null;
//	}

	/**
	 * Detail level parameter adjustments may only be done when both source and result functions
	 * initially had the same number of auto-params and the same total number of parameters
	 * (only complete signature replacement is supported otherwise).  This method is intended to
	 * adjust the result ordinal based upon adjustments which may have already been performed on
	 * the result function causing its number of auto-params to change from when the
	 * conflicts were initially determined.
	 * @param func
	 * @param ordinal
	 * @return adjusted result parameter ordinal
	 */
	private int getAdjustedResultOrdinal(Function resultFunc, Function srcFunc, int ordinal) {
		return resultFunc.getAutoParameterCount() - srcFunc.getAutoParameterCount() + ordinal;
	}

	/**
	 * <CODE>replaceFunctionParameterName</CODE> replaces the name of the indicated
	 * function parameter in program1 with the name from the origin program.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from the origin program.
	 * @param ordinal the index of the parameter to change.
	 * @param monitor the task monitor for notifying the user of progress.
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public void replaceFunctionParameterName(Address originEntryPoint, int ordinal,
			TaskMonitor monitor) throws DuplicateNameException, InvalidInputException {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Parameter p1 = f1.getParameter(getAdjustedResultOrdinal(f1, f2, ordinal));
			Parameter p2 = f2.getParameter(ordinal);
			SourceType source = p2.getSource();
			String fromName = p2.getName();
			for (int i = 0; i < Integer.MAX_VALUE; i++) {
				String newName =
					(i == 0) ? fromName : fromName + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
				try {
					if (p1.isAutoParameter()) {
						// skip
						// TODO: this may not handle all situations where p2 really needs to be inserted !!
						String msg = "Auto-parameter name may not be modified, " +
							p1.getFunction().getName(true) + ":" + p1.getName();
						Msg.error(this, msg);
						errorMsg.append(msg + "\n");
					}
					else {
						p1.setName(newName, source);
						if (i > 0) {
							infoMsg.append("Parameter '" + fromName + "' was merged as '" +
								newName + "' in function " + f1.getName() + ".\n");
						}
					}
					return;
				}
				catch (DuplicateNameException e) {
					continue;
				}
			}
			p1.setName(fromName, source); // Get it to throw the first duplicate name exception.
		}
	}

	/**
	 * <CODE>replaceFunctionParameterDataType</CODE> replaces the data type of the indicated
	 * function parameter in program1 with the data type from the origin program.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from the origin program.
	 * @param ordinal the index of the parameter to change.
	 * @param monitor the task monitor for notifying the user of progress.
	 */
	public void replaceFunctionParameterDataType(Address originEntryPoint, int ordinal,
			TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Parameter p1 = f1.getParameter(getAdjustedResultOrdinal(f1, f2, ordinal));
			Parameter p2 = f2.getParameter(ordinal);
			try {
				try {
					if (f1.hasCustomVariableStorage() &&
						p1.getVariableStorage().isUnassignedStorage()) {
						p1.setDataType(p2.getDataType(), p2.getVariableStorage(), false,
							f2.getSignatureSource());
					}
					else if (p1.isAutoParameter()) {
						// skip
						// TODO: this may not handle all situations where p2 really needs to be inserted !!
						String msg = "Auto-parameter datatype may not be modified, " +
							p1.getFunction().getName(true) + ":" + p1.getName();
						Msg.error(this, msg);
						errorMsg.append(msg + "\n");
					}
					else {
						DataType dt = p2.getDataType();
						if (!f1.hasCustomVariableStorage()) {
							dt = p2.getFormalDataType();
						}
						p1.setDataType(dt, true, false, SourceType.ANALYSIS);
					}
				}
				catch (InvalidInputException e) {
					DataType dt = p2.getDataType();
					if (!f1.hasCustomVariableStorage()) {
						dt = p2.getFormalDataType();
					}
					p1.setDataType(dt, VariableStorage.UNASSIGNED_STORAGE, false,
						SourceType.DEFAULT);
					String msg = "Parameter storage forced to UNASSIGNED for " +
						p1.getFunction().getName(true) + ":" + p1.getName() + ":\n    " +
						e.getMessage();
					Msg.error(this, msg);
					errorMsg.append(msg + "\n");
				}
			}
			catch (InvalidInputException e) {
				String msg =
					"Can't replace parameter datatype for " + p1.getFunction().getName(true) + ":" +
						p1.getName() + ":\n    " + e.getMessage();
				Msg.error(this, msg);
				errorMsg.append(msg + "\n");
			}
		}
	}

	/**
	 * <CODE>replaceFunctionParameterComment</CODE> replaces the comment of the indicated
	 * function parameter in program1 with the comment from the origin program.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from the origin program.
	 * @param ordinal the index of the parameter to change.
	 * @param monitor the task monitor for notifying the user of progress.
	 */
	public void replaceFunctionParameterComment(Address originEntryPoint, int ordinal,
			TaskMonitor monitor) {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Parameter p1 = f1.getParameter(getAdjustedResultOrdinal(f1, f2, ordinal));
			Parameter p2 = f2.getParameter(ordinal);
			if (p1.isAutoParameter()) {
				// skip
				// TODO: this may not handle all situations where p2 really needs to be inserted !!
				String msg = "Auto-parameter comment may not be modified, " +
					p1.getFunction().getName(true) + ":" + p1.getName();
				Msg.error(this, msg);
				errorMsg.append(msg + "\n");
			}
			else {
				p1.setComment(p2.getComment());
			}
		}
	}

	/**
	 * <CODE>replaceFunctionVariable</CODE> replaces the name of the indicated
	 * function variable in program1 with that from the origin program.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from program1.
	 * @param var a variable that is equivalent to the one in program1 to be replaced.
	 * The variable passed here could be from another program.
	 * @param monitor the task monitor for notifying the user of progress.
	 */
	public void replaceFunctionVariable(Address originEntryPoint, Variable var,
			TaskMonitor monitor) {
		if (var instanceof Parameter) {
			throw new IllegalArgumentException(
				"replaceFunctionVariable does not support parameters");
		}
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Variable toVar = findVariable(var, f1.getLocalVariables());
			Variable fromVar = findVariable(var, f2.getLocalVariables());
			// FUTURE: This may need to be changed to hold list of references
			// to the toVar variable so they can be pointed to the fromVar.
			if (toVar != null) {
				f1.removeVariable(toVar);
			}
			if (fromVar != null) {
				try {
					SourceType source = fromVar.getSource();
					VariableUtilities.checkVariableConflict(f1, fromVar,
						fromVar.getVariableStorage(), true);
					f1.addLocalVariable(fromVar, source);
				}
				catch (DuplicateNameException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errorMsg.append("DuplicateNameException replacing function variable: " +
						e.getMessage() + "\n");
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					errorMsg.append("InvalidInputException replacing function variable: " +
						e.getMessage() + "\n");
				}
			}
		}
	}

	/**
	 * <CODE>replaceFunctionVariables</CODE> replaces the
	 * function variables/parameters in program1 with that from the origin program.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from program1.
	 * @param varList the list of variables to replace.
	 * @param monitor the task monitor for notifying the user of progress.
	 * @throws CancelledException if the user canceled the operation via the task monitor.
	 */
	public void replaceVariables(Address originEntryPoint, List<Variable> varList,
			TaskMonitor monitor) throws CancelledException {
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 == null || f2 == null) {
			return;
		}
		boolean replaceParams = false;
		for (Variable var : varList) {
			monitor.checkCanceled();
			if (var instanceof Parameter) {
				replaceParams = true;
				break;
			}
		}
		if (replaceParams) {
			replaceFunctionParameters(originEntryPoint, monitor);
		}
		for (Variable var : varList) {
			monitor.checkCanceled();
			if (!(var instanceof Parameter)) {
				replaceVariable(f2, var, f1);
			}
		}
	}

	/**
	 * Finds a variable in the array that is equivalent to the one specified by var.
	 * @param var a variable that is equivalent to the one in program1 to be changed.
	 * The variable passed here could be from another program.
	 * @param variables the variables to be searched
	 * @return the equivalent variable in the array or null.
	 */
	private Variable findVariable(Variable var, Variable[] variables) {
		int index = Arrays.binarySearch(variables, var);
		if (index >= 0) {
			return variables[index];
		}
		return null;
	}

	/**
	 * <CODE>replaceFunctionVariableName</CODE> replaces the name on the indicated
	 * function variable in program1 with the name from the equivalent variable in program2.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from the origin program.
	 * @param var a variable that is equivalent to the one in program1 to be changed.
	 * The variable passed here could be from another program.
	 * @param monitor the task monitor for notifying the user of progress.
	 * @throws InvalidInputException
	 * @throws DuplicateNameException
	 */
	public void replaceFunctionVariableName(Address originEntryPoint, Variable var,
			TaskMonitor monitor) throws DuplicateNameException, InvalidInputException {
		if (var instanceof Parameter) {
			replaceFunctionParameterName(originEntryPoint, ((Parameter) var).getOrdinal(), monitor);
			return;
		}
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Variable toVar = findVariable(var, f1.getLocalVariables());
			Variable fromVar = findVariable(var, f2.getLocalVariables());
			SourceType source;
			if (fromVar != null) {
				source = fromVar.getSource();
			}
			else if (toVar != null) {
				source = toVar.getSource();
			}
			else {
				source = var.getSource();
			}
			String fromName = (fromVar != null) ? fromVar.getName() : null;
			if (toVar != null) {
				for (int i = 0; i < Integer.MAX_VALUE; i++) {
					String newName =
						(i == 0) ? fromName : fromName + ProgramMerge.SYMBOL_CONFLICT_SUFFIX + i;
					try {
						toVar.setName(newName, source);
						if (i > 0) {
							infoMsg.append("Variable '" + fromName + "' was merged as '" + newName +
								"' in function " + f1.getName() + ".\n");
						}
						return;
					}
					catch (DuplicateNameException e) {
						continue;
					}
				}
				toVar.setName(fromName, source); // Get it to throw the first duplicate name exception.
			}
		}
	}

	/**
	 * <CODE>replaceFunctionVariableDataType</CODE> replaces the data type on the indicated
	 * function variable in program1 with the data type from the equivalent variable in program2.
	 * @param originEntryPoint the entry point address of the function to modify.
	 * This address should be derived from the origin program.
	 * @param var a variable that is equivalent to the one in program1 to be changed.
	 * The variable passed here could be from another program.
	 * @param monitor the task monitor for notifying the user of progress.
	 */
	public void replaceFunctionVariableDataType(Address originEntryPoint, Variable var,
			TaskMonitor monitor) {
		if (var instanceof Parameter) {
			replaceFunctionParameterDataType(originEntryPoint, ((Parameter) var).getOrdinal(),
				monitor);
			return;
		}
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Variable toVar = findVariable(var, f1.getLocalVariables());
			Variable fromVar = findVariable(var, f2.getLocalVariables());
			DataType fromDataType = (fromVar != null) ? fromVar.getDataType() : null;
			if (toVar != null) {
				try {
					toVar.setDataType(fromDataType, SourceType.ANALYSIS);
				}
				catch (InvalidInputException e) {
				}
			}
		}
	}

	/**
	 * <CODE>replaceFunctionVariableComment</CODE> replaces the comment on the indicated
	 * function variable in program1 with the comment from the equivalent variable in program2.
	 * @param originEntryPoint entry point address of the function whose variable is getting the comment replaced.
	 * This address should be derived from the origin program.
	 * @param var a variable that is equivalent to the one in program1 to be changed.
	 * The variable passed here could be from another program.
	 * @param monitor the task monitor for notifying the user of progress.
	 */
	public void replaceFunctionVariableComment(Address originEntryPoint, Variable var,
			TaskMonitor monitor) {
		if (var instanceof Parameter) {
			replaceFunctionParameterComment(originEntryPoint, ((Parameter) var).getOrdinal(),
				monitor);
			return;
		}
		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
		Function f1 = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
		Function f2 = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
		if (f1 != null && f2 != null) {
			Variable toVar = findVariable(var, f1.getLocalVariables());
			Variable fromVar = findVariable(var, f2.getLocalVariables());
			String fromComment = (fromVar != null) ? fromVar.getComment() : null;
			if (toVar != null) {
				toVar.setComment(fromComment);
			}
		}
	}

//	/**
//	 * replaces the program1 function's variables within the offset range
//	 * on the stack with those of program2.
//	 * @param originEntryPoint the entry point address of the function
//	 * This address should be derived from program1.
//	 * @param firstUse only replace the variables with the indicated first use.
//	 * @param range the range of stack offsets where variables should be replaced.
//	 * @param monitor
//	 */
//	public void replaceStackRange(Address originEntryPoint, int firstUse, Range range,
//			TaskMonitor monitor) {
//		Address resultEntryPoint = originToResultTranslator.getAddress(originEntryPoint);
//		Function toFunc = resultProgram.getFunctionManager().getFunctionAt(resultEntryPoint);
//		Function fromFunc = originProgram.getFunctionManager().getFunctionAt(originEntryPoint);
//		Variable[] toVars = toFunc.getVariables(VariableFilter.STACK_VARIABLE_FILTER);
//		Variable[] fromVars = fromFunc.getVariables(VariableFilter.STACK_VARIABLE_FILTER);
//		Arrays.sort(toVars);
//		Arrays.sort(fromVars);
//		MultiComparableArrayIterator<Variable> iter =
//			new MultiComparableArrayIterator<Variable>(new Variable[][] { toVars, fromVars });
//		while (iter.hasNext()) {
//			Variable[] vars = iter.next();
//			Variable var = (vars[0] != null) ? vars[0] : vars[1];
//			int offset = var.getStackOffset();
//			if ((var.getFirstUseOffset() == firstUse) &&
//				(offset >= range.min && offset <= range.max)) {
//				// It is in the range so process this.
//				if (vars[1] == null) {
//					// Remove the var from result.
//					toFunc.removeVariable(vars[0]);
//				}
//				else {
//					replaceVariable(fromFunc, vars[1], toFunc);
//				}
//			}
//		}
//	}

	// **** BOOKMARK methods ****

	/** <CODE>mergeBookmarks</CODE> merges bookmark differences from the origin program to the
	 * result program
	 *  within the specified address set.
	 *
	 * @param originAddressSet the addresses in the origin program where bookmarks are to be
	 * merged to the equivalent address in the result program.
	 *
	 * @param monitor the task monitor for notifying the user of this merge's
	 * progress.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	void mergeBookmarks(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge bookmarks.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Applying Bookmarks...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		// Get the addresses in the set.
		AddressIterator originIter = originAddressSet.getAddresses(true);
		// Get each address in the address set and change the bookmark.
		for (long count = 0; originIter.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			Address originAddress = originIter.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage("Applying Bookmarks...   " + originAddress.toString(true));
				count = 0;
			}
			mergeBookmarksAtAddress(originAddress);
		}
	}

	/** Merges the bookmarks from the origin program into the result
	 *  program at an address equivalent to the originAddress. Merging means replace any existing
	 *  bookmarks in the merge program at the address with the bookmarks
	 *  found in the listing at that address.
	 * @param originAddress the address in the origin program to get the bookmarks from.
	 */
	private void mergeBookmarksAtAddress(Address originAddress) {
		if (originAddress != null) {
			Address resultAddress = originToResultTranslator.getAddress(originAddress);
			BookmarkManager bm1 = resultProgram.getBookmarkManager();
			BookmarkManager bm2 = originProgram.getBookmarkManager();
			try {
				bm1.removeBookmarks(new AddressSet(resultAddress, resultAddress),
					TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (CancelledException e) {
				// DummyAdapter doesn't let cancel occur.
			}
			Bookmark[] marks = bm2.getBookmarks(originAddress);
			for (Bookmark mark : marks) {
				bm1.setBookmark(resultAddress, mark.getTypeString(), mark.getCategory(),
					mark.getComment());
			}
		}
	}

	/**
	 * <CODE>mergeBookmark</CODE> merges the indicated bookmark from the origin program into the
	 * result program at an address equivalent to the originAddress.
	 * Merging means replace any existing bookmark of the specified type for NOTEs
	 * or of the specified type and category for non-NOTE types.
	 * <p>Note: This method merges a single bookmark without affecting
	 * other bookmarks at the indicated address.
	 * @param originAddress the address in the origin program where the bookmark is to be merged.
	 * @param type indicates the type of bookmark to merge.
	 * @param category indicates the category of the bookmark.
	 * @param monitor a task monitor for providing feedback to the user.
	 * @throws CancelledException if the user cancels the bookmark merge from the monitor dialog.
	 */
	public void mergeBookmark(Address originAddress, String type, String category,
			TaskMonitor monitor) throws CancelledException {
		if (originAddress != null) {
			Address resultAddress = originToResultTranslator.getAddress(originAddress);
			BookmarkManager bm1 = resultProgram.getBookmarkManager();
			BookmarkManager bm2 = originProgram.getBookmarkManager();
			if (type.equals(BookmarkType.NOTE)) {
				Bookmark[] books2 = bm2.getBookmarks(originAddress, type);
				if (books2.length == 0) {
					bm1.removeBookmarks(new AddressSet(resultAddress), type, monitor);
				}
				else if (books2.length == 1) {
					bm1.setBookmark(resultAddress, type, books2[0].getCategory(),
						books2[0].getComment());
				}
				else if (books2.length > 1) {
					throw new AssertException("Error in program '" + resultProgram.getName() +
						"'- Shouldn't be multiple notes at a single address. Address=" +
						originAddress.toString());
				}
			}
			else {
				Bookmark book1 = bm1.getBookmark(resultAddress, type, category);
				Bookmark book2 = bm2.getBookmark(originAddress, type, category);
				if (book2 != null) {
					bm1.setBookmark(resultAddress, type, category, book2.getComment());
				}
				else if (book1 != null) {
					bm1.removeBookmark(book1);
				}
			}
		}
	}

	// **** USER DEFINED PROPERTY methods ****

	/** <CODE>mergeProperties</CODE> merges user defined property differences
	 *  within the specified address set.
	 *
	 * @param originAddressSet the addresses to be merged from the origin program.
	 * @param monitor the task monitor for notifying the user of this merge's progress.
	 * @throws CancelledException if user cancels via the monitor.
	 * @throws UnsupportedOperationException if the ProgramMerge translator is not a
	 * "one for one translator".
	 */
	public void mergeProperties(AddressSetView originAddressSet, TaskMonitor monitor)
			throws CancelledException, UnsupportedOperationException {

		if (!originToResultTranslator.isOneForOneTranslator()) {
			String message = originToResultTranslator.getClass().getName() +
				" is not a one for one translator and can't merge properties.";
			throw new UnsupportedOperationException(message);
		}
		monitor.setMessage("Applying Properties...");
		if (originAddressSet.isEmpty()) {
			return;
		}

		// Get the addresses in the set.
		AddressIterator originIter = originAddressSet.getAddresses(true);
		// Get each address in the address set and change the property.
		for (long count = 0; originIter.hasNext() && !monitor.isCancelled(); count++) {
			monitor.checkCanceled();
			Address originAddress = originIter.next();
			if (count == PROGRESS_COUNTER_GRANULARITY) {
				monitor.setMessage("Applying Properties...   " + originAddress.toString(true));
				count = 0;
			}
			mergePropertiesAtAddress(originAddress);
		}
	}

	/** Replaces the user defined properties from the origin program into the result
	 *  program at the address that is equivalent to the origin address.
	 *  Note: To merge properties, there must be a code unit AT the equivalent address
	 *  in the result program.
	 * @param originAddress the address of the code unit to get the properties from in the origin program.
	 */
	private void mergePropertiesAtAddress(Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		resultCu = resultListing.getCodeUnitAt(resultAddress);
		if (resultCu != null) {
			// Remove the existing properties from the merge program's code unit.
			Iterator<String> propNames = resultCu.propertyNames();
			while (propNames.hasNext()) {
				resultCu.removeProperty(propNames.next());
			}

			// Add the originating program's user defined properties on the code unit.
			CodeUnit origCu = originListing.getCodeUnitAt(originAddress);
			if (origCu != null) {
				propNames = origCu.propertyNames();
				while (propNames.hasNext()) {
					propertyName = propNames.next();
					if (propertyName.equals("Bookmarks")) {
						continue; // ignore bookmarks as properties, since the bookmark merge gets these.
					}
					// Handle case where the class for a Saveable property is missing.
					if (originListing.getPropertyMap(propertyName) instanceof UnsupportedMapDB) {
						continue; // ignore property that isn't supported.
					}
					origCu.visitProperty(this, propertyName);
				}
			}
		}
	}

	/** Replaces the user defined properties from the specified origin address in the origin program
	 * to the equivalent result address in the result program.
	 * Note: To merge properties, there must be a code unit AT the equivalent address
	 * in the result program.
	 * @param originAddress the address of the code unit to get the properties from in the origin program.
	 */
	public void mergeUserProperty(String userPropertyName, Address originAddress) {
		Address resultAddress = originToResultTranslator.getAddress(originAddress);
		PropertyMapManager resultPmm = resultProgram.getUsrPropertyManager();
		PropertyMapManager originPmm = originProgram.getUsrPropertyManager();
		PropertyMap resultOpm = resultPmm.getPropertyMap(userPropertyName);
		PropertyMap originOpm = originPmm.getPropertyMap(userPropertyName);
		Object resultObject = null;
		Object originObject = null;
		if (resultOpm != null) {
			resultObject = getProperty(resultOpm, resultAddress);
		}
		if (originOpm != null) {
			originObject = getProperty(originOpm, originAddress);
		}
		if (!SystemUtilities.isEqual(resultObject, originObject)) {
			if (resultObject != null && resultOpm != null) {
				resultOpm.remove(resultAddress);
			}
			if (originObject != null) {
				if (resultOpm == null) {
					try {
						resultOpm =
							resultPmm.createObjectPropertyMap(userPropertyName, Saveable.class);
					}
					catch (DuplicateNameException e) {
						throw new RuntimeException(e);
					}
				}
				setProperty(resultOpm, resultAddress, originObject);
			}
		}
	}

	private Object getProperty(PropertyMap map, Address address) {
		if (map instanceof VoidPropertyMap) {
			return ((VoidPropertyMap) map).getNextPropertyAddress(address);
		}
		else if (map instanceof ObjectPropertyMap) {
			return ((ObjectPropertyMap) map).getObject(address);
		}
		else if (map instanceof LongPropertyMap) {
			try {
				return new Long(((LongPropertyMap) map).getLong(address));
			}
			catch (NoValueException e) {
				return null;
			}
		}
		else if (map instanceof IntPropertyMap) {
			try {
				return new Integer(((IntPropertyMap) map).getInt(address));
			}
			catch (NoValueException e) {
				return null;
			}
		}
		else if (map instanceof StringPropertyMap) {
			return ((StringPropertyMap) map).getString(address);
		}
		return null;
	}

	private void setProperty(PropertyMap map, Address address, Object property) {
		if (map instanceof VoidPropertyMap) {
			((VoidPropertyMap) map).add(address);
		}
		else if (map instanceof ObjectPropertyMap) {
			((ObjectPropertyMap) map).add(address, (Saveable) property);
		}
		else if (map instanceof LongPropertyMap) {
			((LongPropertyMap) map).add(address, ((Long) property).longValue());
		}
		else if (map instanceof IntPropertyMap) {
			((IntPropertyMap) map).add(address, ((Integer) property).intValue());
		}
		else if (map instanceof StringPropertyMap) {
			((StringPropertyMap) map).add(address, (String) property);
		}
	}

	// *******************************************************************
	// The following are the methods for the PropertyVisitor interface.
	// *******************************************************************
	/** Set the property on the merge program's code unit if the named property
	 *  is a void property type.
	 */
	@Override
	public void visit() {
		resultCu.setProperty(propertyName);
	}

	/** Set the property on the merge program's code unit if the named property
	 *  is a String property type.
	 * @param value the value for the named property.
	 */
	@Override
	public void visit(String value) {
		resultCu.setProperty(propertyName, value);
	}

	/** Set the property on the merge program's code unit if the named property
	 *  is an Object property type.
	 * @param value the value for the named property.
	 */
	@Override
	public void visit(Object value) {
		String message = "Could Not Merge Property.\n" + "Can't merge property, \"" + propertyName +
			"\", with value of " + value;
		errorMsg.append(message);
	}

	/** Set the property on the merge program's code unit if the named property
	 *  is an Object property type.
	 * @param value the value for the named property.
	 */
	@Override
	public void visit(Saveable value) {
		resultCu.setProperty(propertyName, value);
	}

	/** Set the property on the merge program's code unit if the named property
	 *  is an int property type.
	 * @param value the value for the named property.
	 */
	@Override
	public void visit(int value) {
		resultCu.setProperty(propertyName, value);
	}

}
