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
//The script is called from several scripts to use selected instructions with or without operands and constants (depending on the script
//that called it) and build a combined mask/value buffer.
//Memory is then searched looking for this combined value buffer that represents the selected instructions.
//This automates the process of searching through memory for a particular ordering of instructions by hand.
//@category Search.InstructionPattern

import java.util.ArrayList;
import java.util.LinkedHashMap;

import ghidra.app.plugin.processors.sleigh.SleighDebugLogger;
import ghidra.app.plugin.processors.sleigh.SleighDebugLogger.SleighDebugMode;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.ImproperUseException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

public class SearchBaseExtended extends GhidraScript {

	//holds the mask and value for all the mnemonics, or commands like cmp, jmp, jnz etc
	ArrayList<Case> mnemonics = new ArrayList<>();

	/*
	 * Holds the masks and values for all the operands. The arraylist portion will correspond to the operand number. An example is 
	 * arraylist.get(0) will refer to the first operand. Arraylist.get(1) will return the second operands data. The previous commands will
	 * give you a hashmap that maps the mnemonics MVCase object to its operands, if they exist. For example to get the first operand for the 
	 * second mnemonic that was seen you would call arraylist.get(0).get(mnemonicArrayList.get(1)); That will return the MVCase that refers to
	 * operand. I set it up this was to conserve memory and allow for a dynamically growing collection.
	 */
	ArrayList<LinkedHashMap<Case, OperandCase>> ops =
		new ArrayList<>();//holds masks and values for all operands. 

	ArrayList<Case> db = new ArrayList<>();//holds the search results.

	//These control the detail at which a scan is performed. 
	//They determine how specific the instructions must match the currently selected ones
	ArrayList<SLMaskControl> controlList = new ArrayList<>();

	@Override
	public void run() throws Exception {
		loadSelectedInstructions();
		executeSearch();
	}

	public void run(boolean mneonics, boolean op1, boolean op2, boolean constants) {
		controlList = new ArrayList<>();
		controlList.add(new SLMaskControl(mneonics, op1, op2, constants));
		loadSelectedInstructions();
		executeSearch();
	}

	public void run(ArrayList<SLMaskControl> control) {
		controlList = control;
		loadSelectedInstructions();
		executeSearch();
	}

	public void clearResults() {
		db = new ArrayList<>();
	}

	public void setState(SLMaskControl newState) {
		controlList = new ArrayList<>();
		controlList.add(newState);
	}

	public void setState(ArrayList<SLMaskControl> newState) {
		controlList = newState;
	}

	public void loadSelectedInstructions() {
		if (currentProgram == null || currentSelection == null) {
			return;
		}

		try {
			//Builds object that is used to extract all the instructions masks and values
			SleighDebugLogger logger = null;

			//Grabs the AddressRange for the first continuous selection of instructions
			AddressRange addrRange = currentSelection.getFirstRange();
			if (addrRange == null) {
				return;
			}//makes sure that something was returned

			//Creates a list that is used to determine the location of the instructions starting byte
			Listing list = currentProgram.getListing();

			Address tempAddr = addrRange.getMinAddress();//sets the beginning scan address

			/*
			 * The purpose of this while loop is to iterate through the memory that is currently selected by user. 
			 * All the instructions within this selection range are extracted and corresponding masks made from them.
			 * These masks will then be used to search through memory to find instructions of the same type.
			 */
			while (tempAddr.compareTo(addrRange.getMaxAddress()) <= 0) {

				//Determines if current location is start of instruction, tempIns will be null if not beginning of instruction
				Instruction tempIns = list.getInstructionAt(tempAddr);

				if (tempIns != null) {//means that current address is start of an instruction

					logger =
						new SleighDebugLogger(currentProgram, tempAddr, SleighDebugMode.VERBOSE);
					if (logger.parseFailed()) {
						break;
					}

					//This takes care of the headers
					byte[] mask = logger.getInstructionMask();
					byte[] value = logger.getMaskedBytes(mask);
					if (mask == null || value == null) {
						break;
					}//need to move on to next byte, not sure if this is right command to use

					//Builds a structure representing the recently found instruction mask and value
					Case tCase = new Case();
					tCase.mask = mask;
					tCase.value = value;
					tCase.textRep = tempIns.getMnemonicString();
					mnemonics.add(tCase); //adds the mnemonic mask and value to the arraylist

					//Gets a code unit which can be used to determine if the operands are constants.
					CodeUnit cu = list.getCodeUnitAt(tempAddr);

					//Iterates through all the operands for the currently selected instruction and stores them accordingly
					for (int x = 1; x <= logger.getNumOperands(); x++) {
						mask = logger.getOperandValueMask(x - 1);
						value = logger.getMaskedBytes(mask);

						if (mask == null || value == null) {
							break;
						}//move on to next instruction

						//Builds case to store the operands mask and value
						OperandCase otCase = new OperandCase();
						otCase.mask = mask;
						otCase.value = value;
						//Object hey = tempIns.getDefaultOperandRepresentationList(x-1);
						otCase.textRep = tempIns.getDefaultOperandRepresentation(x - 1);

						//Determines if the given operand is a constant value. If it is a constant then proper flag is set.
						if (cu.getScalar(x - 1) != null) {
							otCase.constant = true;
						}

						//Determines if current structure is large enough to hold new operand, if it isn't increases structure size
						if (ops.size() < x && ops.size() > -1) {
							ops.add(new LinkedHashMap<Case, OperandCase>());
						}

						//Adds the operand to the data-structure with a mapping to the instruction mnemonic extracted earlier in line 87
						ops.get(x - 1).put(tCase, otCase);
					}
					//Increments the address pointer to point to the beginning of next instruction.
					tempAddr = tempAddr.add(tempIns.getLength());
				}
				else {

					//Increments the address pointer by 1
					//This would be hit if the tempAddr didn't get offset correctly.
					tempAddr.addWrap(1);
				}
			}
		}
		catch (Exception e) {
			println(e.getMessage());
		}
	}

	//performs the application of filters and search instructions for matches. Doesn't load instructions or fill the controlList object.
	//Must have mnemonics, ops and controlList populated prior to running this method.
	public void executeSearch() {

		//Applies the filters provided through the controlList object to the instructions provided through the mnemonics and ops structures.
		MaskValueCase finalSearchString = getFinalMaskAndValue(mnemonics, ops, controlList);

		String valueString = new String();
		String maskString = new String();

		for (byte element : finalSearchString.value) {
			valueString = valueString.concat(toHexString(element, true, false)) + " ";
		}

		for (byte element : finalSearchString.mask) {
			maskString = maskString.concat(toHexString(element, true, false)) + " ";
		}

		printf("Final Search Bytes: ");
		println(valueString);
		printf("Final Search Mask: ");
		println(maskString);

		//Searches memory for matches to provided instructions with given filters. db structure is populated with the results.
		findLocations(finalSearchString, db);

		//Displays results in a table.
		Address[] tableArray = new Address[db.size()];
		for (int x = 0; x < db.size(); x++) {
			tableArray[x] = db.get(x).addr;
		}

		try {
			show(tableArray);
		}
		catch (ImproperUseException iue) {
			// Do nothing; this code should only be run headed, anyway
		}
	}

	/*
	 * Builds the mask and value byte streams for a single instruction that is represented by the mnemonic entered into the first parameter.
	 * 
	 * That mnemonic is used as a key to withdrawal the operands from the data-structure and the SLMaskControl contains the filter information to be
	 * applied to the instruction.
	 */
	private MaskValueCase buildSingleInstructionMask(Case mnemonic,
			ArrayList<LinkedHashMap<Case, OperandCase>> localOperands, SLMaskControl localState) {

		byte[] tempMask = new byte[mnemonic.mask.length];
		byte[] tempValue = new byte[mnemonic.value.length];

		//Applies the mnemonic's value and mask if needed
		if (localState.useMnemonic) {
			tempValue = byteArrayOr(tempValue, mnemonic.value);
			tempMask = byteArrayOr(tempMask, mnemonic.mask);
		}
		//Applies the first operands mask and value to running stream if needed
		if (localState.useOp1 && localOperands.size() >= 1 &&
			localOperands.get(0).get(mnemonic) != null) {

			OperandCase temp = localOperands.get(0).get(mnemonic);

			if (localState.useConst || !temp.constant) {

				if (temp.value != null && temp.mask != null && tempValue != null &&
					tempMask != null) {
					tempValue = byteArrayOr(tempValue, temp.value);
					tempMask = byteArrayOr(tempMask, temp.mask);
				}
			}
		}
		//Applies the second operands mask and value to running stream if needed
		if (localState.useOp2 && localOperands.size() >= 2 &&
			localOperands.get(1).get(mnemonic) != null) {

			OperandCase temp = localOperands.get(1).get(mnemonic);

			if (localState.useConst || !temp.constant) {

				if (temp.value != null && temp.mask != null && tempValue != null &&
					tempMask != null) {
					tempValue = byteArrayOr(tempValue, temp.value);
					tempMask = byteArrayOr(tempMask, temp.mask);
				}
			}
		}

		MaskValueCase tempCase = new MaskValueCase();
		tempCase.mask = tempMask;
		tempCase.value = tempValue;

		return tempCase;
	}

	/*
	 * Combines all the masks in the data-structure together into a single byte stream. This stream is used to search memory.
	 */
	private MaskValueCase combineInstructionMasks(ArrayList<byte[]> masks, ArrayList<byte[]> values,
			int length) {

		if (masks.size() != values.size()) {
			throw new IllegalArgumentException();
		}

		int index = 0;

		/*
		 * This portion of code takes the masks and values from each of the different commands and concatenates them together to form
		 * a single mask and value byte array. This byte array is then used to scan memory to look for other sequences of commands.
		 */
		byte[] finalValueArray = new byte[length];
		byte[] finalMaskArray = new byte[length];
		for (int x = 0; x < values.size(); x++) { //iterates through each mnemonic

			for (int i = 0; i < values.get(x).length && index < length; i++) { //iterate through the mnemonics bytes
				finalValueArray[index] = values.get(x)[i];
				finalMaskArray[index] = masks.get(x)[i];
				index++;
			}
		}

		MaskValueCase tempFinalParams = new MaskValueCase();
		tempFinalParams.mask = finalMaskArray;
		tempFinalParams.value = finalValueArray;

		return tempFinalParams;
	}

	/*
	 * Calculates the final mask and value byte streams. These streams are then used to search through memory to look for similar 
	 * assembly instructions.
	 */
	private MaskValueCase getFinalMaskAndValue(ArrayList<Case> privateMnemonics,
			ArrayList<LinkedHashMap<Case, OperandCase>> localOperands,
			ArrayList<SLMaskControl> control) {

		ArrayList<byte[]> masks = new ArrayList<>();
		ArrayList<byte[]> values = new ArrayList<>();

		//used for storing the byte stream currently being work on prior to being added to final data structure
		int totalLength = 0;

		boolean continueFilter = true;//controls whether the last mask given will be applied on the rest of the mnemonics if the controlList structure is smaller than mnemonics

		if (privateMnemonics == null || localOperands == null || control == null) {
			throw new IllegalArgumentException("Null Structure");
		}

		//TODO Need to do some thorough checking on values entered into the control and mnemonics
		//TODO Need to make sure that all possible cases of unequal amounts are considered.

		/*
		 * This loop will scan through the mnemonics and apply the provided MaskControls.
		 * 
		 * The masks will be applied from the arraylist until there aren't any remaining in the list. At this point
		 * a mask of all falses will be applied. This will in effect ignore rest of the mnemonics
		 * 
		 * TODO Apply a switch that will allow the last mask in the array to be applied to rest of the mnemonics within selection.
		 */
		for (int x = 0; x < privateMnemonics.size(); x++) {

			MaskValueCase result = new MaskValueCase();

			if (x < control.size()) {
				//need to apply the filter from control		
				result = buildSingleInstructionMask(privateMnemonics.get(x), localOperands,
					control.get(x));
			}
			else if (continueFilter) {
				//apply the last available mask in the control structure
				result = buildSingleInstructionMask(privateMnemonics.get(x), localOperands,
					control.get(control.size() - 1));
			}
			else {
				//apply an empty filter basically ignoring
				result = buildSingleInstructionMask(privateMnemonics.get(x), localOperands,
					new SLMaskControl(false, false, false, false));
			}

			if (result.value.length == result.mask.length) {
				masks.add(result.mask);
				values.add(result.value);
				totalLength += result.value.length;
			}
		}

		return combineInstructionMasks(masks, values, totalLength);
	}

	/*
	 * Populates the database with the locations where the specified byte arrays are found.
	 * The first parameter should only have two elements. Element 0 should contain mask and element 1 
	 * contain the value.
	 * 
	 * The second parameter gets populated with the results of the search.
	 */
	private void findLocations(MaskValueCase searchArrays, ArrayList<Case> localDatabase) {

		if (currentProgram == null || localDatabase == null || searchArrays == null) {
			throw new IllegalArgumentException("Null Data-Structure");
		}
		if (searchArrays.mask.length != searchArrays.value.length) {
			throw new IllegalArgumentException("Mask and value lengths are different.");
		}

		if (containsOnBit(searchArrays.mask)) {
			Memory mem = currentProgram.getMemory();

			//Gets the start and end address to search through
			Address endAddress = currentProgram.getMaxAddress();

			Address currentPosition = currentProgram.getMinAddress();
			while (currentPosition.compareTo(endAddress) < 0) {

				//Searches memory for the given mask and value.
				currentPosition = mem.findBytes(currentPosition, endAddress, searchArrays.value,
					searchArrays.mask, true, monitor);

				//Determines if a new location was found.
				if (currentPosition == null) {
					break;
				}

				Case temp = new Case();
				temp.mask = searchArrays.mask;
				temp.value = searchArrays.value;
				temp.addr = currentPosition;
				localDatabase.add(temp);

				currentPosition = currentPosition.add(1);
			}
		}
		else {
			return;
		}
	}

	/*
	 * Used for determining if there is a "On" bit in a byte stream.
	 * 
	 * This is necessary because if you do a memory search for a mask with no "on" bit then it will return every memory address.
	 */
	private boolean containsOnBit(byte[] array) {

		for (byte element : array) {
			Byte temp = new Byte(element);
			int value = temp.intValue();
			if (value != 0) {
				return true;
			}
		}

		return false;
	}

	/*
	 * Takes two arrays of bytes and performs a bitwise or operation and returns the result. Returns null if the arguments aren't of same length.
	 */
	private byte[] byteArrayOr(byte[] arr1, byte[] arr2) {
		byte[] result = new byte[arr1.length];

		if (arr1.length != arr2.length) {
			return null;
		}

		for (int x = 0; x < arr1.length; x++) {
			result[x] = (byte) (arr1[x] | arr2[x]);
		}

		return result;
	}

	/*
	 * Used for storing data about an instructions mnemonic
	 */
	public class Case {
		public Address addr;
		public byte[] mask;
		public byte[] value;
		public String textRep;
	}

	public class OperandCase extends Case {
		public boolean constant = false;
	}

	private class MaskValueCase {
		public byte[] mask;
		public byte[] value;
	}

	/*
	 * Represents a filter for a single instruction. 
	 * Controls which portions of the instruction will be used when performing the search through memory.
	 */
	public class SLMaskControl {
		boolean useMnemonic = true;
		boolean useOp1 = false;
		boolean useOp2 = false;
		boolean useConst = false;

		public SLMaskControl() {
		}

		public SLMaskControl(boolean mnemonic, boolean useop1, boolean useop2, boolean constant) {
			useMnemonic = mnemonic;
			useOp1 = useop1;
			useOp2 = useop2;
			useConst = constant;
		}
	}
}
