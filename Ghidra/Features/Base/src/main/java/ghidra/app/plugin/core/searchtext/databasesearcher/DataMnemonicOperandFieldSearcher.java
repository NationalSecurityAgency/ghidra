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

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DataMnemonicOperandFieldSearcher extends ProgramDatabaseFieldSearcher {
	private DataIterator iterator;
	private CodeUnitFormat format;

	private final boolean doMnemonics;
	private final boolean doOperands;
	private Program program;

	static DataMnemonicOperandFieldSearcher createDataMnemonicOnlyFieldSearcher(Program program,
			ProgramLocation startLoc, AddressSetView set, boolean forward, Pattern pattern,
			CodeUnitFormat format) {
		return new DataMnemonicOperandFieldSearcher(program, startLoc, set, forward, pattern,
			format, true, false);

	}

	static DataMnemonicOperandFieldSearcher createDataOperandOnlyFieldSearcher(Program program,
			ProgramLocation startLoc, AddressSetView set, boolean forward, Pattern pattern,
			CodeUnitFormat format) {
		return new DataMnemonicOperandFieldSearcher(program, startLoc, set, forward, pattern,
			format, false, true);

	}

	static DataMnemonicOperandFieldSearcher createDataMnemonicAndOperandFieldSearcher(
			Program program, ProgramLocation startLoc, AddressSetView set, boolean forward,
			Pattern pattern, CodeUnitFormat format) {

		return new DataMnemonicOperandFieldSearcher(program, startLoc, set, forward, pattern,
			format, true, true);
	}

	private DataMnemonicOperandFieldSearcher(Program program, ProgramLocation startLoc,
			AddressSetView set, boolean forward, Pattern pattern, CodeUnitFormat format,
			boolean doMnemonics, boolean doOperands) {

		super(pattern, forward, startLoc, set);
		this.program = program;
		this.format = format;
		this.doMnemonics = doMnemonics;
		this.doOperands = doOperands;

		if (set != null) {
			iterator = program.getListing().getDefinedData(set, forward);
		}
		else {
			iterator = program.getListing().getDefinedData(startLoc.getAddress(), forward);
		}
	}

	@Override
	protected Address advance(List<ProgramLocation> currentMatches) {
		Data data = iterator.next();
		Address nextAddress = null;
		if (data != null) {
			nextAddress = data.getMinAddress();
			findMatchesForCurrentAddress(data, currentMatches);
		}
		return nextAddress;
	}

	private void findMatchesForCurrentAddress(Data data, List<ProgramLocation> currentMatches) {
		StringBuffer searchStrBuf = new StringBuffer();
		String mnemonicString = "";
		String operandString = "";
		if (doMnemonics) {
			mnemonicString = data.getMnemonicString();
			searchStrBuf.append(mnemonicString);
		}
		if (doOperands) {
			Object value = data.getValue();
			if (value != null) {
				operandString = format.getDataValueRepresentationString(data);
				if (searchStrBuf.length() != 0) {
					searchStrBuf.append(' ');
				}
				searchStrBuf.append(operandString);
			}
		}

		Matcher matcher = pattern.matcher(searchStrBuf.toString());
		Address address = data.getMinAddress();
		while (matcher.find()) {
			int startIndex = matcher.start();
			int endIndex = matcher.end();
			if (startIndex == mnemonicString.length() && doMnemonics) {
				// don't match on space separator
			}
			else if (startIndex < mnemonicString.length()) {
				addMnemonicMatch(currentMatches, mnemonicString, address, startIndex, endIndex);
			}
			else {
				addOperandMatch(data, currentMatches, mnemonicString, operandString, address,
					startIndex);
			}
		}
	}

	private void addOperandMatch(Data data, List<ProgramLocation> currentMatches,
			String mnemonicString, String operandString, Address address, int index) {
		if (!doOperands) {
			return;
		}
		currentMatches.add(new OperandFieldLocation(program, address, data.getComponentPath(),
			null, operandString, 0, index - mnemonicString.length() - 1));
	}

	private void addMnemonicMatch(List<ProgramLocation> currentMatches, String mnemonicString,
			Address address, int index, int endIndex) {
		if (!doMnemonics) {
			return;
		}
		// If not doing operands, make sure the match does not span into the operand field
		if (endIndex > mnemonicString.length()) {
			return;
		}
		currentMatches.add(new MnemonicFieldLocation(program, address, null, null, mnemonicString,
			index));
	}
}
