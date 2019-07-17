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
package ghidra.app.plugin.core.searchmem.mask;

import java.util.*;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

/**
 * 
 */
class MaskGenerator {

	/**
	 * Holds the mask and value for all the mnemonics, or commands like cmp,
	 * jmp, jnz etc.
	 */
	private List<MaskValue> mnemonics = new ArrayList<>();

	/*
	 * Holds the masks and values for all the operands. The arraylist portion will correspond to the operand number. An example is 
	 * arraylist.get(0) will refer to the first operand. Arraylist.get(1) will return the second operands data. The previous commands will
	 * give you a hashmap that maps the mnemonics MVCase object to its operands, if they exist. For example to get the first operand for the 
	 * second mnemonic that was seen you would call arraylist.get(0).get(mnemonicArrayList.get(1)); That will return the MVCase that refers to
	 * operand. I set it up this was to conserve memory and allow for a dynamically growing collection.
	 *
	 */
	private List<LinkedHashMap<MaskValue, OperandMaskValue>> ops = new ArrayList<>();

	/**
	 * 
	 */
	private SLMaskControl maskControl;

	/**
	 * Constructor.
	 * 
	 * @param maskControl
	 */
	public MaskGenerator(SLMaskControl maskControl) {
		this.maskControl = maskControl;
	}

	/**
	 * Returns the mask settings for the selected instructions.
	 * 
	 * @param program
	 * @param selection
	 * @return
	 */
	public MaskValue getMask(Program program, ProgramSelection selection) {
		loadSelectedInstructions(program, selection);

		return getFinalMaskAndValue();
	}

	/**
	 * Loads whatever instructions have been selected and stores the mnemonics,
	 * operands, and mask values for subsequent use.
	 *
	 * @param program
	 * @param selection
	 */
	private void loadSelectedInstructions(Program program, ProgramSelection selection) {

		// First get the program listing.
		Listing listing = program.getListing();

		// Now check to make sure the user hasn't selected multiple regions; if they have,
		// LET THEM KNOW.  This situation is not allowed so pop up a dialog and cancel the whole show.
		if (selection.getNumAddressRanges() > 1) {
			Msg.showWarn(this, null, "Multiple Regions Selected",
				"Selected instructions must be contiguous");
		}

		// If we're here, we have only 1 selection range, so proceed.  Use an instruction
		// iterator to loop over all addresses, processing each in turn.
		AddressRange addrRange = selection.getFirstRange();
		AddressSet addrSet = new AddressSet(addrRange);
		InstructionIterator iter = listing.getInstructions(addrSet, true);
		while (iter.hasNext()) {

			// Grab the next instruction...
			Instruction instr = iter.next();
			Address addr = instr.getAddress();

			// Extract some info from the address.  If there's a problem, don't exit the entire loop, 
			// just move on to the next item.
			SleighDebugLogger logger =
				new SleighDebugLogger(program, addr, SleighDebugMode.VERBOSE);
			if (logger.parseFailed()) {
				break;
			}

			// Get the bytes and mask info related to this instruction.
			byte[] mask = logger.getInstructionMask();
			byte[] value = logger.getMaskedBytes(mask);

			MaskValue mnemonicMask = new MnemonicMaskValue(mask, value, instr.getMnemonicString());
			mnemonics.add(mnemonicMask);

			//Gets a code unit which can be used to determine if the operands are constants.
			CodeUnit cu = listing.getCodeUnitAt(addr);
			storeOperands(instr, logger, mnemonicMask, cu);
		}
	}

	/**
	 * Populates objects with mask/operand info for future use.
	 * 
	 * @param instruction
	 * @param logger
	 * @param maskValue
	 * @param cu
	 */
	private void storeOperands(Instruction instruction, SleighDebugLogger logger,
			MaskValue maskValue, CodeUnit cu) {

		// Iterates through all the operands for the currently selected 
		// instruction and stores them.
		for (int i = 1; i <= logger.getNumOperands(); i++) {
			byte[] mask = logger.getOperandValueMask(i - 1);
			byte[] value = logger.getMaskedBytes(mask);

			if (mask == null || value == null) {
				return;
			}

			// Builds case to store the operands mask and value
			OperandMaskValue opMaskValue = new OperandMaskValue(mask, value,
				instruction.getDefaultOperandRepresentation(i - 1));

			// Determines if the given operand is a constant value. If it is 
			// a constant then proper flag is set.
			//
			// NOTE: Addresses and Scalars are both treated as constants.
			if (cu.getScalar(i - 1) != null || cu.getAddress(i - 1) != null) {
				opMaskValue.setConstant(true);
			}

			LinkedHashMap<MaskValue, OperandMaskValue> mnemonicToOpMap = null;

			// Do a check on the size of the instruction map (ops).  The size of ops must be 
			// equal to the max number of operands across all instructions.  ie: if we have an 
			// instruction with 4 operands, then ops.size() better equal 4.  So do a check here - 
			// if ops isn't large enough to handle the number of ops in this instruction, add
			// another map struct.
			if (ops.size() < i) {
				mnemonicToOpMap = new LinkedHashMap<>();
				ops.add(mnemonicToOpMap);
			}
			else {
				mnemonicToOpMap = ops.get(i - 1);
			}

			// Adds the operand to the data-structure with a mapping to the 
			// instruction mnemonic extracted earlier
			mnemonicToOpMap.put(maskValue, opMaskValue);
		}
	}

	/**
	 * Builds the mask and value byte streams for a single instruction that is
	 * represented by the mnemonic entered into the first parameter.
	 * 
	 * That mnemonic is used as a key to withdrawal the operands from the
	 * data-structure and the SLMaskControl contains the filter information to
	 * be applied to the instruction.
	 *
	 * @param mnemonic
	 * @return
	 */
	private MaskValue buildSingleInstructionMask(MaskValue mnemonic) {

		byte[] mnemonicMask = mnemonic.getMask();
		byte[] mnemonicValue = mnemonic.getValue();

		MaskValue result =
			new MaskValue(new byte[mnemonicMask.length], new byte[mnemonicValue.length]);

		// Applies the mnemonic's value and mask if needed.
		result.orMask(mnemonicMask);
		result.orValue(mnemonicValue);

		if (!maskControl.useOperands()) {
			return result;
		}

		for (int i = 0; i < ops.size(); i++) {
			Map<MaskValue, OperandMaskValue> opMap = ops.get(i);
			if (opMap != null) {
				OperandMaskValue op = opMap.get(mnemonic);
				addToMask(op, result);
			}
		}

		return result;
	}

	/**
	 * 
	 * @param op
	 * @param result
	 */
	private void addToMask(OperandMaskValue op, MaskValue result) {
		if (op == null) {
			return;
		}

		if (op.isConstant() && !maskControl.useConst()) {
			return; // not using constants
		}

		byte[] op1Mask = op.getMask();
		byte[] op1Value = op.getValue();
		if (op1Value != null && op1Mask != null) {
			result.orMask(op1Mask);
			result.orValue(op1Value);
		}
	}

	/**
	 * Combines all the masks in the data-structure together into a single byte
	 * stream.
	 *
	 * @param masks
	 * @param values
	 * @param length
	 * @return
	 */
	private MaskValue combineInstructionMasks(List<byte[]> masks, List<byte[]> values, int length) {

		if (masks.size() != values.size()) {
			throw new IllegalArgumentException();
		}

		/*
		 * This portion of code takes the masks and values from each of the 
		 * different commands and concatenates them together to form
		 * a single mask and value byte array. 
		 */
		byte[] finalValueArray = new byte[length];
		byte[] finalMaskArray = new byte[length];
		int index = 0;
		for (int x = 0; x < values.size(); x++) { //iterates through each mnemonic

			for (int i = 0; i < values.get(x).length && index < length; i++) {
				finalValueArray[index] = values.get(x)[i];
				finalMaskArray[index] = masks.get(x)[i];
				index++;
			}
		}

		return new MaskValue(finalMaskArray, finalValueArray);
	}

	/**
	 * Calculates the final mask and value byte streams. These streams can then
	 * be used to search through memory to look for similar assembly
	 * instructions.
	 */
	private MaskValue getFinalMaskAndValue() {

		List<byte[]> masks = new ArrayList<>();
		List<byte[]> values = new ArrayList<>();
		int totalLength = 0;
		for (int i = 0; i < mnemonics.size(); i++) {

			MaskValue result = buildSingleInstructionMask(mnemonics.get(i));
			byte[] mask = result.getMask();
			byte[] value = result.getValue();
			if (value.length == mask.length) {
				masks.add(mask);
				values.add(value);
				totalLength += value.length;
			}
		}

		return combineInstructionMasks(masks, values, totalLength);
	}

	/**
	 * 
	 */
	private class MnemonicMaskValue extends MaskValue {

		/**
		 * 
		 * @param mask
		 * @param value
		 * @param textRep
		 */
		public MnemonicMaskValue(byte[] mask, byte[] value, String textRep) {
			super(mask, value, textRep);
		}
	}

	/**
	 * 
	 */
	private class OperandMaskValue extends MaskValue {
		private boolean constant = false;

		/**
		 * 
		 * @param mask
		 * @param value
		 * @param textRep
		 */
		OperandMaskValue(byte[] mask, byte[] value, String textRep) {
			super(mask, value, textRep);
		}

		void setConstant(boolean constant) {
			this.constant = constant;
		}

		boolean isConstant() {
			return constant;
		}
	}

}
