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
package ghidra.app.plugin.core.instructionsearch.model;

import java.util.*;

import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;

/**
 * This is the data model that {@link InstructionSearchDialog} instances use
 * when building their displays.
 */
public class InstructionSearchData extends Observable {

	// This is the entire set of instructions that will be searched on when/if the user
	// selects the 'search' or 'search all' buttons. Each time a new selection is made, this 
	// list will be updated.
	private List<InstructionMetadata> instructions = new ArrayList<InstructionMetadata>();

	// Specifies the type of model updates this class can issue.  
	//
	// A RELOAD type should trigger any GUI clients to perform a full reload; this is issued when
	// the instruction set has changed completely.
	//
	// An UPDATE type should leave the instruction table as-is, and just cause the preview panel
	// to be updated (this is generally when users have toggled masks but the instruction set
	// remains the same).
	public static enum UpdateType {
		RELOAD, UPDATE
	}

	/**
	 * If this data model is being run in a headed environment, this method
	 * should be called to have the model be notified when users have toggled
	 * masks via the gui.
	 * 
	 * @param table the table to register for
	 */
	public void registerForGuiUpdates(InstructionTable table) {
		table.getModel().addTableModelListener(e -> applyMasks(table));
	}

	/**
	 * This method ensures that all mask settings in the dialog are applied to
	 * the {@link #instructions} list.
	 * 
	 * @see InstructionSearchData
	 */
	public void applyMasks(InstructionTable table) {
		for (int row = 0; row < instructions.size(); row++) {
			storeInstructionMask(table, row);
		}

		modelChanged(UpdateType.UPDATE);
	}

	/**
	 * Parses the given {@link AddressRange} from the given {@link Program} to
	 * extract all instructions; results are stored in the local
	 * {@link InstructionMetadata} list.
	 * 
	 * @param program the current program
	 * @param addressRange the addresses to load instructions for
	 * @throws InvalidInputException if there's an error parsing the
	 *             instructions
	 */
	public void load(Program program, AddressRange addressRange) throws InvalidInputException {

		// first clear out any current instructions.
		instructions.clear();

		// Do some initial checks on the program and addresses we want to load instructions
		// for.  If these are invalid, no need to proceed.
		if (program == null || addressRange == null || addressRange.getLength() == 0) {
			return;
		}

		// Now we have to use the sleigh logger to parse each of the code units in the 
		// requested address set.
		Listing listing = program.getListing();
		AddressSet addrSet = new AddressSet(addressRange);
		CodeUnitIterator cuIter = listing.getCodeUnits(addrSet, true);

		// Do a quick check to see if we have any valid code units in the selection.  If not,
		// display an error message.
		if (!cuIter.hasNext()) {
			throw new InvalidInputException("No instructions found in selection.");
		}

		TaskLauncher.launchModal("Loading Instructions", monitor -> {

			SleighDebugLogger logger;
			monitor.setIndeterminate(true);

			while (cuIter.hasNext()) {
				if (monitor.isCancelled()) {
					return;
				}

				CodeUnit cu = cuIter.next();

				InstructionMetadata instructionMetadata;

				// If this CU is an instruction, we can use the Sleigh debug logger to build the 
				// mask info.  If not, we don't need to create anything complex for masking - it's either
				// on or off.
				if (cu instanceof Instruction) {
					logger =
						new SleighDebugLogger(program, cu.getAddress(), SleighDebugMode.VERBOSE);
					if (logger.parseFailed()) {
						Msg.showError(this, null, "Parsing error",
							"Error parsing instruction: " + cu.toString());
						return;
					}

					instructionMetadata = getInstructionMetadata(logger, cu);
					if (instructionMetadata != null) {
						instructions.add(instructionMetadata);
					}
					processOperands(logger, cu, instructionMetadata);

				}
				else if (cu instanceof Data) {
					try {
						instructionMetadata = getInstructionMetadata(cu);
						if (instructionMetadata != null) {
							instructions.add(instructionMetadata);
						}
					}
					catch (InvalidInputException e) {
						Msg.showError(this, null, "Parsing error",
							"Error parsing data: " + cu.toString());
						return;
					}
				}
			}
		});

		modelChanged(UpdateType.RELOAD);
	}

	/**
	 * Clears out the instruction list in this model, and fires off a
	 * notification to subscribers.
	 * 
	 */
	public void clearAndReload() {

		// No need to do anything if the instructions are already empty.
		if (instructions.isEmpty()) {
			return;
		}
		instructions.clear();

		modelChanged(UpdateType.RELOAD);
	}

	/**
	 * Returns the list of all instructions.
	 * 
	 * @return the list of instructions
	 * 
	 */
	public List<InstructionMetadata> getInstructions() {
		return instructions;
	}

	/**
	 * Replaces the instructions in this model with the given list, and fires
	 * off a notification to subscribers.
	 * 
	 * @param instructions the instructions to replace
	 */
	public void setInstructions(List<InstructionMetadata> instructions) {
		this.instructions = instructions;
		modelChanged(UpdateType.RELOAD);
	}

	/**
	 * Returns the maximum number of operands across all instructions. ie: if
	 * one instruction has 2 operands, another has 3, and another has 5, this
	 * will return 5.
	 * 
	 * @return the max number of operands
	 */
	public int getMaxNumOperands() {

		int numOperands = 0;
		for (InstructionMetadata instruction : instructions) {
			int numOperandsTemp = instruction.getOperands().size();
			if (numOperandsTemp > numOperands) {
				numOperands = numOperandsTemp;
			}
		}

		return numOperands;
	}

	/**
	 * Returns the mask and value for all instructions, combined into one binary
	 * string.
	 * 
	 * @return the combined string
	 */
	public String getCombinedString() {
		return getAllMasks().toBinaryString();
	}

	/**
	 * Returns the mask for all instructions as a binary string.
	 * 
	 * @return the mask string
	 */
	public String getMaskString() {
		return getAllMasks().getMaskAsBinaryString();
	}

	/**
	 * Returns the value for all instructions as a binary string.
	 * 
	 * @return the value string
	 */
	public String getValueString() {
		return getAllMasks().getValueAsBinaryString();
	}

	/**
	 * Masks all operands in the instruction set that have the given type.
	 * 
	 * @param operandType {@link OperandType}
	 */
	public void maskOperandsByType(int operandType) {
		for (InstructionMetadata instruction : instructions) {
			List<OperandMetadata> operands = instruction.getOperands();
			for (OperandMetadata operand : operands) {

				switch (operandType) {
					case OperandType.SCALAR:
						if (OperandType.isScalar(operand.getOpType())) {
							operand.setMasked(true);
						}
						break;
					case OperandType.ADDRESS:
						if (OperandType.isAddress(operand.getOpType())) {
							operand.setMasked(true);
						}
				}
			}
		}
	}

	/**
	 * Masks all operands in the instruction set.
	 */
	public void maskAllOperands() {
		for (InstructionMetadata instruction : instructions) {
			List<OperandMetadata> operands = instruction.getOperands();
			for (OperandMetadata operand : operands) {
				operand.setMasked(true);
			}
		}
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Must be called whenever the set of instructions has changed. When this
	 * happens we have to notify subscribers.
	 * 
	 * @param updateType reload or update change type
	 */
	private void modelChanged(UpdateType updateType) {
		this.setChanged();
		this.notifyObservers(updateType);
	}

	/**
	 * Gets the mask values for the given instruction, and stores them in the
	 * {@link InstructionSearchData} object.
	 * 
	 * @param table the table containing the instructions
	 * @param row the specific instruction row
	 */
	private void storeInstructionMask(InstructionTable table, int row) {

		// Store the mnemonic information.
		storeMnemonicMask(table, row);

		for (int i = 0; i < getMaxNumOperands(); i++) {

			// Make sure we have a valid set of data for this operand.  If not, continue to 
			// the next one.
			if (table.getCellData(row, i + 1) == null) {
				continue;
			}

			// The operand is good and has valid data, so process it.
			storeOperandMask(table, row, i);
		}
	}

	/**
	 * Gets the mask value set by the user for the given operand, and stores it
	 * in the {@link InstructionSearchData} object.
	 * 
	 * @param table the table containing the instructions
	 * @param row the specific instruction row
	 * @param col the specific operand column
	 */
	private void storeOperandMask(InstructionTable table, int row, int col) {

		// Make sure the row isn't out of bounds.
		if (row >= instructions.size()) {
			return;
		}

		// Make sure the column isn't out of bounds.
		if (col >= instructions.get(row).getOperands().size()) {
			return;
		}

		instructions.get(row).getOperands().get(col).setMasked(
			table.getCellData(row, col + 1).getState().equals(OperandState.MASKED));
	}

	/**
	 * Gets the mask value set by the user for the given mnemonic, and stores it
	 * in the {@link InstructionSearchData} object.
	 * 
	 * @param table the table containing the instructions
	 * @param row the specific instruction row
	 */
	private void storeMnemonicMask(InstructionTable table, int row) {

		// Note: magic number 0 is used since the mnemonic column is always the first one.
		if (table.getCellData(row, 0) == null) {
			return;
		}

		OperandState mnemonicMaskState = table.getCellData(row, 0).getState();
		instructions.get(row).setMasked(mnemonicMaskState.equals(OperandState.MASKED));
	}

	/**
	 * Builds a {@link MaskContainer} containing the mask and value byte arrays
	 * for all instructions.
	 * 
	 * @return the mask container object
	 */
	private MaskContainer getAllMasks() {

		List<byte[]> masks = new ArrayList<byte[]>();
		List<byte[]> values = new ArrayList<byte[]>();

		for (int i = 0; i < instructions.size(); i++) {
			MaskContainer result = buildSingleInstructionMask(instructions.get(i));

			if (result == null) {
				continue;
			}

			masks.add(result.getMask());
			values.add(result.getValue());
		}

		return combineInstructionMasks(masks, values);
	}

	/**
	 * Extracts mask/value information from the sleigh logger and stores it in a
	 * {@link InstructionMetadata} object.
	 *
	 * @param logger the sleigh debug logger
	 * @param codeUnit the code unit containing the instruction
	 * @return the metadata for the instruction
	 */
	private InstructionMetadata getInstructionMetadata(SleighDebugLogger logger,
			CodeUnit codeUnit) {

		// Get the mask/value for the mnemonic; if either is null then we have a problem
		// and should just move on to the next instruction.
		byte[] mask = logger.getInstructionMask();
		byte[] value = logger.getMaskedBytes(mask);

		return createInstructionMetadata(codeUnit, mask, value, true);
	}

	/**
	 * Creates {@link InstructionMetadata} from a CodeUnit that has no
	 * additional mask information available (as with the other method of this
	 * name that gets mask info from the {@link SleighDebugLogger}).
	 *
	 * @param codeUnit the code unit containing the instruction
	 * @return the metadata for the instruction
	 * @throws InvalidInputException if there's an issue parsing the instruction
	 */
	private InstructionMetadata getInstructionMetadata(CodeUnit codeUnit)
			throws InvalidInputException {

		// Get the size of the code unit; this tells us the size of the mask array that needs
		// to be created.
		int cuSize = codeUnit.getLength();

		// Create mask/value arrays for the code unit.  The value array is initialized with the 
		// byte value of the code unit; the mask is filled with -1's.
		byte[] mask = new byte[cuSize];
		Arrays.fill(mask, (byte) -1);
		byte[] value = null;
		try {
			value = codeUnit.getBytes();
		}
		catch (MemoryAccessException e) {
			throw new InvalidInputException("Error reading bytes at: " +
				codeUnit.getAddressString(false, false) + " (possibly unititialized data?)");
		}

		return createInstructionMetadata(codeUnit, mask, value, false);
	}

	/**
	 * Creates an {@link InstructionMetadata} object based on the given inputs.
	 * No special processing is done here, it's just creating a data container
	 * for what is given.
	 * 
	 * @param codeUnit the code unit containing the instruction
	 * @param mask the byte mask
	 * @param value the byte value
	 * @param instruction true if this is an instruction
	 * @return the metadata for the instruction
	 */
	private InstructionMetadata createInstructionMetadata(CodeUnit codeUnit, byte[] mask,
			byte[] value, boolean instruction) {

		MaskContainer masks = new MaskContainer(mask, value);
		InstructionMetadata instructionMetadata = new InstructionMetadata(masks);

		instructionMetadata.setAddr(codeUnit.getAddress());
		instructionMetadata.setTextRep(codeUnit.getMnemonicString());
		instructionMetadata.setIsInstruction(instruction);
		return instructionMetadata;
	}

	/**
	 * Iterates over all operands in the given instruction, creating
	 * {@link OperandMetadata} for each.
	 * 
	 * @param logger the sleigh debug logger
	 * @param codeUnit the code unit containing the operands
	 * @param instructionMetadata The structure to fill with results
	 */
	private void processOperands(SleighDebugLogger logger, CodeUnit codeUnit,
			InstructionMetadata instructionMetadata) {

		for (int i = 0; i < logger.getNumOperands(); i++) {
			OperandMetadata operandMetadata = getOperandMetadata(logger, codeUnit, i);
			if (operandMetadata != null) {
				instructionMetadata.getOperands().add(operandMetadata);
			}
		}
	}

	/**
	 * Constructs a {@link OperandMetadata} object for the given operand.
	 *
	 * @param logger the sleigh debug logger
	 * @param codeUnit the code unit containing the operand
	 * @param operand the index of the operand
	 * @return the metadata for the operand
	 */
	private OperandMetadata getOperandMetadata(SleighDebugLogger logger, CodeUnit codeUnit,
			int operand) {

		// First get the mask/value strings for this operand.  The logger easily gives us these; 
		// note that the getMaskedBytes method is simply applying the operand mask to the full
		// instruction value string, to return a string that consists of the full value string
		// with everything BUT The operand masked out.
		byte[] mask = logger.getOperandValueMask(operand);
		byte[] value = logger.getMaskedBytes(mask);

		// If we're here, then things are good, so set the mask information in the container.
		OperandMetadata operandMetadata = new OperandMetadata();
		MaskContainer masks = new MaskContainer(mask, value);
		operandMetadata.setMaskContainer(masks);

		// If this code unit is an instruction there's some additional information we can
		// extract.
		if (codeUnit instanceof Instruction) {
			Instruction instr = (Instruction) codeUnit;
			operandMetadata.setTextRep(instr.getDefaultOperandRepresentation(operand));
			operandMetadata.setOpType(instr.getOperandType(operand));
		}

		return operandMetadata;
	}

	/**
	 * Creates a {@link MaskContainer} object for the given instruction,
	 * containing all the pertinent mask and value information. This mask
	 * container contains the mask/value arrays for the entire instruction, both
	 * mnemonic and operands.
	 * 
	 * @param instruction the instruction to parse
	 */
	private MaskContainer buildSingleInstructionMask(InstructionMetadata instruction) {

		// Do some initial data validation checks.  If we don't have a valid instruction with
		// valid mask and value arrays, we can't do anything, so just return.
		if (instruction == null) {
			return null;
		}
		if (instruction.getMaskContainer() == null) {
			return null;
		}
		if (instruction.getMaskContainer().getMask() == null ||
			instruction.getMaskContainer().getValue() == null) {
			return null;
		}

		// Now Create the mask/value arrays. Populating these is the main point of this method; these 
		// will be placed in the return object when we're done. Note that they're initialized to
		// be the size of the mask/value arrays in the given instruction; these are guaranteed
		// to be the correct size (if they're not, there's a serious problem).
		byte[] tempMask = new byte[instruction.getMaskContainer().getMask().length];
		byte[] tempValue = new byte[instruction.getMaskContainer().getValue().length];

		//////////////////
		// MNEMONIC
		//////////////////

		// First look at the mnemonic.  If it's supposed to be masked, then we want to leave the 
		// mnemonic portion of the arrays set to 0 (they were set to 0 above, when initialized).  If
		// not masked, then we need to put the actual mnemonic bytes in the temp/value arrays.
		if (!instruction.isMasked()) {
			tempValue = instruction.getMaskContainer().getValue();
			tempMask = instruction.getMaskContainer().getMask();
		}

		//////////////////
		// OPERANDS
		//////////////////

		// Now do for the operands what we just did for the mnemonic; loop over each one and add its
		// mask/value to the main arrays depending on the mask setting.
		for (OperandMetadata operand : instruction.getOperands()) {

			// If masked, then just leave the value of the bits at 0.  Continue to the next
			// operand.
			if (operand.isMasked()) {
				continue;
			}

			// Now do some due diligence with null checks...
			if (operand.getMaskContainer().getValue() == null ||
				operand.getMaskContainer().getMask() == null || tempValue == null ||
				tempMask == null) {
				continue;
			}

			// Everything looks good, so apply the operand masks.
			tempValue = InstructionSearchUtils.byteArrayOr(tempValue,
				operand.getMaskContainer().getValue());
			tempMask =
				InstructionSearchUtils.byteArrayOr(tempMask, operand.getMaskContainer().getMask());
		}

		// Now create a new struct for the mask and return to the caller.
		MaskContainer result;
		try {
			result = new MaskContainer(tempMask, tempValue);
		}
		catch (IllegalArgumentException e) {
			// If we're here, then there's a problem with the mask/value arrays we used to 
			// create the mask container.  Just return null.
			return null;
		}

		return result;
	}

	/**
	 * Creates a {@link MaskContainer} object representing the bytes to be
	 * searched for, along with any masking information.
	 * 
	 * @param masks List of all masks for all instructions
	 * @param values List of all values for all instructions
	 */
	private MaskContainer combineInstructionMasks(List<byte[]> masks, List<byte[]> values) {

		// If the byte arrays aren't the same size then we have a problem; definitely throw
		// something.
		if (masks.size() != values.size()) {
			throw new IllegalArgumentException();
		}

		// Now figure out the size of the final array we need to construct.  We 
		// could use ArrayList objects instead but that would be too inefficient.
		int totalLength = 0;
		for (int i = 0; i < values.size(); i++) {
			totalLength += values.get(i).length;
		}

		// This takes the masks and values from each command and concats them together to form
		// a single mask and value byte array. 
		byte[] value = new byte[totalLength];
		byte[] mask = new byte[totalLength];

		int index = 0;
		for (int x = 0; x < values.size(); x++) {
			for (int i = 0; i < values.get(x).length && index < totalLength; i++) {
				value[index] = values.get(x)[i];
				mask[index] = masks.get(x)[i];
				index++;
			}
		}

		MaskContainer container;
		try {
			container = new MaskContainer(mask, value);
		}
		catch (IllegalArgumentException e) {
			return null;
		}

		return container;
	}

	/**
	 * Searches through instructions in the given program for a specific byte
	 * pattern. If found, returns the instruction. i
	 * 
	 * @param program the program to search
	 * @param searchBounds the addresses to search
	 * @param taskMonitor the task monitor
	 * @param forwardSearch if true, search through addresses forward
	 * @throws IllegalArgumentException if there's a problem parsing addresses
	 * @return the instruction, or null if not found
	 */
	public InstructionMetadata search(ProgramPlugin plugin, AddressRange searchBounds,
			TaskMonitor taskMonitor, boolean forwardSearch) {

		if (plugin == null || plugin.getCurrentProgram() == null) {
			throw new IllegalArgumentException("Program provided to search is null");
		}

		// Do a quick check to make sure the search bounds are within the bounds of the 
		// program.
		if (searchBounds.getMinAddress().compareTo(
			plugin.getCurrentProgram().getMinAddress()) < 0 ||
			searchBounds.getMaxAddress().compareTo(
				plugin.getCurrentProgram().getMaxAddress()) > 0) {
			throw new IllegalArgumentException(
				"Search bounds are not valid; must be within the bounds of the program.");
		}

		MaskContainer maskContainer = this.getAllMasks();

		if (InstructionSearchUtils.containsOnBit(maskContainer.getMask())) {
			if (forwardSearch) {
				return searchForward(plugin, searchBounds, taskMonitor, maskContainer);
			}

			return searchBackward(plugin, searchBounds, taskMonitor, maskContainer);

		}

		return null;
	}

	/**
	 * Searches for a specific byte pattern in the positive direction.
	 * 
	 * @param plugin the instruction pattern search plugin
	 * @param searchBounds the addresses to search
	 * @param taskMonitor the task monitor
	 * @param maskContainer the bytes to search for
	 * @return the instruction, or null if not found
	 */
	private InstructionMetadata searchForward(ProgramPlugin plugin, AddressRange searchBounds,
			TaskMonitor taskMonitor, MaskContainer maskContainer) {

		Address startAddress = searchBounds.getMinAddress();
		Address endAddress = searchBounds.getMaxAddress();
		Address currentPosition = plugin.getProgramLocation().getByteAddress().next();

		taskMonitor.setShowProgressValue(false);// no need to show the number of bytes
		taskMonitor.setProgress(0);

		// The maximum value for the monitor is the number of bytes to be checked - this will 
		// NOT always be the size of the range passed-in. If the cursor is in the middle of
		// the range already, then only the number of bytes in the range PAST the cursor will 
		// will be checked.
		long max = searchBounds.getLength();
		if (currentPosition.compareTo(searchBounds.getMinAddress()) > 0) {
			max = searchBounds.getMaxAddress().subtract(currentPosition);
		}
		taskMonitor.setMaximum(max);

		// Move the cursor to the beginning of the range if it is currently short of it. We don't
		// want to search for any addresses that aren't in the search bounds.
		if (currentPosition.compareTo(startAddress) < 0) {
			currentPosition = startAddress;
		}

		while (currentPosition.compareTo(endAddress) < 0) {

			// Search program memory for the given mask and val.
			currentPosition = plugin.getCurrentProgram().getMemory().findBytes(currentPosition,
				endAddress, maskContainer.getValue(), maskContainer.getMask(), true, taskMonitor);

			// If no match was found, currentPosition will be null.
			if (currentPosition == null) {
				break;
			}

			// Otherwise construct a new entry to put in our results table.
			MaskContainer masks =
				new MaskContainer(maskContainer.getMask(), maskContainer.getValue());
			InstructionMetadata temp = new InstructionMetadata(masks);
			temp.setAddr(currentPosition);

			return temp;
		}

		return null;
	}

	/**
	 * Searches for a specific byte pattern in the reverse direction.
	 * 
	 * @param plugin the instruction pattern search plugin
	 * @param searchBounds the addresses to search
	 * @param taskMonitor the task monitor
	 * @param maskContainer the bytes to search for
	 * @return the instruction, or null if not found
	 */
	private InstructionMetadata searchBackward(ProgramPlugin plugin, AddressRange searchBounds,
			TaskMonitor taskMonitor, MaskContainer maskContainer) {

		Address startAddress = searchBounds.getMaxAddress();
		Address endAddress = searchBounds.getMinAddress();
		Address currentPosition = plugin.getProgramLocation().getByteAddress().previous();

		taskMonitor.setShowProgressValue(false);
		taskMonitor.setProgress(0);

		// The maximum value for the monitor is the number of bytes to be checked - this will 
		// NOT always be the size of the range passed-in. If the cursor is in the middle of
		// the range already, then only the number of bytes in the range BEFORE the cursor will 
		// will be checked.
		long max = searchBounds.getLength();
		if (currentPosition.compareTo(searchBounds.getMaxAddress()) < 0) {
			max = currentPosition.subtract(searchBounds.getMinAddress());
		}
		taskMonitor.setMaximum(max);

		// Move the cursor to the end of the range if it is currently past it. We don't
		// want to search for any addresses that aren't in the search bounds.
		if (currentPosition.compareTo(startAddress) > 0) {
			currentPosition = startAddress;
		}

		while (currentPosition.compareTo(endAddress) > 0) {

			// Search program memory for the given mask and val.
			currentPosition = plugin.getCurrentProgram().getMemory().findBytes(currentPosition,
				endAddress, maskContainer.getValue(), maskContainer.getMask(), false, taskMonitor);

			// If no match was found, currentPosition will be null.
			if (currentPosition == null) {
				break;
			}

			// Otherwise construct a new entry to put in our results table.
			MaskContainer masks =
				new MaskContainer(maskContainer.getMask(), maskContainer.getValue());
			InstructionMetadata temp = new InstructionMetadata(masks);
			temp.setAddr(currentPosition);

			return temp;
		}

		return null;
	}

	/**
	 * Searches the given program for a specific byte pattern, returning all
	 * found results
	 *
	 * @param program the program to search
	 * @param searchBounds the addresses to search
	 * @param taskMonitor the task monitor
	 * @throws IllegalArgumentException if there's a problem parsing addresses
	 * @return list of found instructions
	 */
	public List<InstructionMetadata> search(Program program, AddressRange searchBounds,
			TaskMonitor taskMonitor) throws IllegalArgumentException {

		List<InstructionMetadata> searchResults = new ArrayList<>();

		if (program == null) {
			throw new IllegalArgumentException("Program provided to search is null");
		}

		// Do a quick check to make sure the search bounds are within the bounds of the 
		// program.
		if (searchBounds.getMinAddress().compareTo(program.getMinAddress()) < 0 ||
			searchBounds.getMaxAddress().compareTo(program.getMaxAddress()) > 0) {
			throw new IllegalArgumentException(
				"Search bounds are not valid; must be within the bounds of the program.");
		}

		MaskContainer maskContainer = this.getAllMasks();

		if (InstructionSearchUtils.containsOnBit(maskContainer.getMask())) {
			Memory mem = program.getMemory();

			// Get the min and max address positions - we'll use these
			// for iterating.
			Address currentPosition = searchBounds.getMinAddress();
			Address endAddress = searchBounds.getMaxAddress();

			while (currentPosition.compareTo(endAddress) < 0) {

				// Search program memory for the given mask and val.
				currentPosition = mem.findBytes(currentPosition, endAddress,
					maskContainer.getValue(), maskContainer.getMask(), true, taskMonitor);

				// If no match was found, currentPosition will be null.
				if (currentPosition == null) {
					break;
				}

				// Otherwise construct a new entry to put in our results table.
				MaskContainer masks =
					new MaskContainer(maskContainer.getMask(), maskContainer.getValue());
				InstructionMetadata temp = new InstructionMetadata(masks);
				temp.setAddr(currentPosition);
				searchResults.add(temp);

				// And update the position pointer so we'll process the next item.
				currentPosition = currentPosition.next();
			}
		}

		return searchResults;
	}
}
