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
package ghidra.app.plugin.core.instructionsearch;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.plugin.core.instructionsearch.api.InstructionSearchApi_Yara;
import ghidra.app.plugin.core.instructionsearch.model.*;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * API for users who wish to perform instruction searching without the GUI. 
 * 
 * Limitations:	
 * 		1) Searches may only be performed on a single program.
 * 		2) Only a single address range may be searched for.
 * 
 * Results:
 * 		Can be returned in 2 ways: 
 * 			1) As a list of addresses representing the location of search matches.
 * 			2) As a string (either binary or hex) representing the search string to be used.
 * 		The latter results option is useful if using another tool to perform the search (ie yara).
 * 
 * Extending:
 * 		This class may be extended to provide an api for specific searching formats.  There is
 * 		currently an extension for Yara: {@link InstructionSearchApi_Yara}.
 * 
 */
public class InstructionSearchApi {

	/**
	 * Searches the given program for the instructions specified by the given address range.  No 
	 * filtering of results is performed; all matches regardless of operand type will be 
	 * returned.
	 * 
	 * @param program
	 * @param addressRange
	 * @return a list of addresses indicating starting positions of matches.
	 * @throws InvalidInputException 
	 */
	public final List<Address> search(Program program, AddressRange addressRange)
			throws InvalidInputException {

		InstructionSearchData searchData = new InstructionSearchData();

		searchData.load(program, addressRange);

		// Now need to loop over all initialized memory ranges and search for results.  Add each
		// set of results to our InstructionMetadata list.
		List<InstructionMetadata> searchResults = new ArrayList<InstructionMetadata>();
		AddressRangeIterator rangeIter =
			program.getMemory().getLoadedAndInitializedAddressSet().getAddressRanges();

		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			searchResults.addAll(searchData.search(program, range, TaskMonitor.DUMMY));
		}

		return InstructionSearchUtils.toAddressList(searchResults);
	}

	/**
	 * Searches the given program for the instructions specified by the given address range, with
	 * masking set according to the given {@link MaskSettings} object
	 * 
	 * @param program
	 * @param addressRange
	 * @param maskSettings
	 * 
	 * @return a list of addresses indicating starting positions of matches.
	 * @throws InvalidInputException 
	 */
	public final List<Address> search(Program program, AddressRange addressRange,
			MaskSettings maskSettings) throws InvalidInputException {

		InstructionSearchData searchData = new InstructionSearchData();

		searchData.load(program, addressRange);

		if (maskSettings.isMaskOperands()) {
			searchData.maskAllOperands();
		}
		else {
			if (maskSettings.isMaskScalars()) {
				searchData.maskOperandsByType(OperandType.SCALAR);
			}
			if (maskSettings.isMaskAddresses()) {
				searchData.maskOperandsByType(OperandType.ADDRESS);
			}
		}

		// Now need to loop over all initialized memory ranges and search for results.  Add each
		// set of results to our InstructionMetadata list.
		List<InstructionMetadata> searchResults = new ArrayList<InstructionMetadata>();
		AddressRangeIterator rangeIter =
			program.getMemory().getLoadedAndInitializedAddressSet().getAddressRanges();

		while (rangeIter.hasNext()) {
			AddressRange range = rangeIter.next();
			searchResults.addAll(searchData.search(program, range, TaskMonitor.DUMMY));
		}

		return InstructionSearchUtils.toAddressList(searchResults);
	}

	/**
	 * Returns a binary string representing the bytes in the address range provided. 
	 * 
	 * @param program
	 * @param addressRange
	 * @return
	 * @throws InvalidInputException 
	 */
	public final String getBinarySearchString(Program program, AddressRange addressRange)
			throws InvalidInputException {

		MaskSettings maskSettings = new MaskSettings(false, false, false);
		String searchString = getBinarySearchString(program, addressRange, maskSettings);

		return searchString;
	}

	/**
	 * Returns a hex version of the bytes representing the address range given.
	 * 
	 * @param program
	 * @param addressRange
	 * @return
	 * @throws InvalidInputException 
	 */
	public final String getHexSearchString(Program program, AddressRange addressRange)
			throws InvalidInputException {
		return InstructionSearchUtils.toHexNibblesOnly(getBinarySearchString(program, addressRange)).toString();
	}

	/**
	 * Returns a binary string representing the bytes in the address range provided, with masked 
	 * bits set according to the given {@link MaskSettings} object.
	 * 
	 * Note: Masked bits will be represented by a '.' character.
	 * 
	 * @param maskSettings
	 * @param addressRange
	 * @param maskSettings
	 * @return
	 * @throws InvalidInputException 
	 */
	public final String getBinarySearchString(Program program, AddressRange addressRange,
			MaskSettings maskSettings) throws InvalidInputException {

		InstructionSearchData searchData = new InstructionSearchData();
		searchData.load(program, addressRange);

		if (maskSettings.isMaskOperands()) {
			searchData.maskAllOperands();
		}
		else {
			if (maskSettings.isMaskScalars()) {
				searchData.maskOperandsByType(OperandType.SCALAR);
			}
			if (maskSettings.isMaskAddresses()) {
				searchData.maskOperandsByType(OperandType.ADDRESS);
			}
		}

		return searchData.getCombinedString();
	}

	/**
	 * Returns a hex version of the bytes representing the address range given.
	 * 
	 * @param program
	 * @param addressRange
	 * @param maskSettings
	 * @return
	 * @throws InvalidInputException 
	 */
	public final String getHexSearchString(Program program, AddressRange addressRange,
			MaskSettings maskSettings) throws InvalidInputException {
		return InstructionSearchUtils.toHexNibblesOnly(
			getBinarySearchString(program, addressRange, maskSettings)).toString();
	}

	/**
	 * Opens the search dialog and populates it with instructions located in the
	 * address range given. A program must be loaded in Ghidra for this to work, as determining 
	 * the instructions would be impossible otherwise.
	 * 
	 * @param addresses the addresses to load
	 * @param tool the current plugin tool
	 */
	public void loadInstructions(AddressSet addresses, PluginTool tool) {

		InstructionSearchDialog searchDialog = new InstructionSearchDialog(
			InstructionSearchUtils.getInstructionSearchPlugin(tool), "Search Dialog", null);
		tool.showDialog(searchDialog);
		searchDialog.loadBytes(addresses);
	}

	/**
	 * Opens the search dialog and populates it with instructions represented by the
	 * bytes given. A program must be loaded in Ghidra for this to work, as determining the 
	 * instructions would be impossible otherwise. 
	 * 
	 * @param bytes binary or hex string representing the bytes to be loaded
	 */
	public void loadInstructions(String bytes, PluginTool tool) {

		InstructionSearchDialog searchDialog = new InstructionSearchDialog(
			InstructionSearchUtils.getInstructionSearchPlugin(tool), "Search Dialog", null);
		tool.showDialog(searchDialog);
		searchDialog.loadBytes(bytes);
	}

}
