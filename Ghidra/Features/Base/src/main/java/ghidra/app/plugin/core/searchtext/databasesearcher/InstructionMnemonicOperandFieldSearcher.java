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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

public class InstructionMnemonicOperandFieldSearcher extends ProgramDatabaseFieldSearcher {
	private InstructionIterator iterator;
	private final CodeUnitFormat format;
	private final boolean doMnemonics;
	private final boolean doOperands;
	private Program program;

	public static InstructionMnemonicOperandFieldSearcher createInstructionMnemonicOnlyFieldSearcher(
			Program program, ProgramLocation startLoc, AddressSetView set, boolean forward,
			Pattern pattern, CodeUnitFormat format) {
		return new InstructionMnemonicOperandFieldSearcher(program, startLoc, set, forward,
			pattern, format, true, false);

	}

	public static InstructionMnemonicOperandFieldSearcher createInstructionOperandOnlyFieldSearcher(
			Program program, ProgramLocation startLoc, AddressSetView set, boolean forward,
			Pattern pattern, CodeUnitFormat format) {
		return new InstructionMnemonicOperandFieldSearcher(program, startLoc, set, forward,
			pattern, format, false, true);

	}

	public static InstructionMnemonicOperandFieldSearcher createInstructionMnemonicAndOperandFieldSearcher(
			Program program, ProgramLocation startLoc, AddressSetView set, boolean forward,
			Pattern pattern, CodeUnitFormat format) {

		return new InstructionMnemonicOperandFieldSearcher(program, startLoc, set, forward,
			pattern, format, true, true);
	}

	private InstructionMnemonicOperandFieldSearcher(Program program, ProgramLocation startLoc,
			AddressSetView set, boolean forward, Pattern pattern, CodeUnitFormat format,
			boolean doMnemonics, boolean doOperands) {

		super(pattern, forward, startLoc, set);
		this.program = program;
		this.format = format;
		this.doMnemonics = doMnemonics;
		this.doOperands = doOperands;

		if (set != null) {
			iterator = program.getListing().getInstructions(set, forward);
		}
		else {
			iterator = program.getListing().getInstructions(startLoc.getAddress(), forward);
		}
	}

	@Override
	protected Address advance(List<ProgramLocation> currentMatches) {
		Instruction instruction = iterator.hasNext() ? iterator.next() : null;
		Address nextAddress = null;
		if (instruction != null) {
			nextAddress = instruction.getMinAddress();
			findMatchesForCurrentAddress(instruction, currentMatches);
		}
		return nextAddress;
	}

	private void findMatchesForCurrentAddress(Instruction instruction,
			List<ProgramLocation> currentMatches) {
		String mnemonicString = instruction.getMnemonicString();
		String[] opStrings = getOperandStrings(instruction);
		Matcher matcher = pattern.matcher(combineStrings(mnemonicString, opStrings));
		Address address = instruction.getMinAddress();
		while (matcher.find()) {
			int startIndex = matcher.start();
			int endIndex = matcher.end();
			if (startIndex <= mnemonicString.length()) {
				addMnemonicMatch(currentMatches, address, mnemonicString, startIndex, endIndex);
			}
			else {
				startIndex -= mnemonicString.length() + 1;
				addOperandMatch(instruction, currentMatches, opStrings, address, startIndex);
			}
		}
	}

	private void addOperandMatch(Instruction instruction, List<ProgramLocation> currentMatches,
			String[] opStrings, Address address, int index) {
		if (!doOperands) {
			return;
		}
		int opIndex = findOpIndex(opStrings, index);
		int charOffset = findCharOffset(index, opIndex, opStrings);
		currentMatches.add(new OperandFieldLocation(program, address, null,
			instruction.getAddress(opIndex), opStrings[opIndex], opIndex, charOffset));
	}

	private void addMnemonicMatch(List<ProgramLocation> currentMatches, Address address,
			String mnemonicString, int startIndex, int endIndex) {
		if (!doMnemonics) {
			return;
		}
		// If not doing operands, make sure the match does not span into the operand field
		if (!doOperands && endIndex > mnemonicString.length()) {
			return;
		}

		currentMatches.add(new MnemonicFieldLocation(program, address, null, null, mnemonicString,
			startIndex));
	}

	private int findCharOffset(int index, int opIndex, String[] opStrings) {
		int totalBeforeOpIndex = 0;
		for (int i = 0; i < opIndex; i++) {
			totalBeforeOpIndex += opStrings[i].length();
		}
		return index - totalBeforeOpIndex;
	}

	private int findOpIndex(String[] opStrings, int index) {
		int totalSoFar = 0;
		for (int i = 0; i < opStrings.length; i++) {
			if (index < totalSoFar + opStrings[i].length()) {
				return i;
			}
			totalSoFar += opStrings[i].length();
		}
		return opStrings.length - 1;
	}

	private CharSequence combineStrings(String mnemonicString, String[] opStrings) {
		if (opStrings.length == 0) {
			return mnemonicString;
		}
		StringBuffer buf = new StringBuffer(mnemonicString);
		buf.append(' ');
		for (String string : opStrings) {
			buf.append(string);
		}
		return buf.toString();
	}

	private String[] getOperandStrings(Instruction instruction) {
		int nOperands = instruction.getNumOperands();
		String[] opStrings = new String[nOperands];
		for (int i = 0; i < nOperands; i++) {
			opStrings[i] = format.getOperandRepresentationString(instruction, i);
			if (instruction.getPrototype().hasDelimeter(i)) {
				opStrings[i] = opStrings[i] + instruction.getSeparator(i + 1);
			}
		}
		// check for separator before first operand
		if (nOperands > 0) {
			String separator = instruction.getSeparator(0);
			if (separator != null) {
				opStrings[0] = separator + opStrings[0];
			}
		}
		return opStrings;
	}

}
