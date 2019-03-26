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
package ghidra.feature.vt.api.markupitem;

import static ghidra.feature.vt.gui.util.VTMatchApplyChoices.HighestSourcePriorityChoices.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.VTMarkupItem;
import ghidra.feature.vt.api.main.VTMarkupItemStatus;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.symbol.SourceType;

public class FunctionSignatureMarkupParameterName1Test extends AbstractFunctionSignatureMarkupTest {

	// Default Apply Markup Options
	// ============================
	// Data Match Data Type .......... = Replace Undefined Data Only
	// End of Line Comment ........... = Add To Existing
	// Function Call Fixup ........... = Replace
	// Function Calling Convention ... = Replace If Same Language
	// Function Inline ............... = Replace
	// Function Name ................. = Replace Always
	// Function No Return ............ = Replace
	// Function Parameter Comments ... = Add To Existing
	// Function Parameter Data Types . = Replace Undefined Data Types Only
	// Function Parameter Names ...... = User Priority Replace
	// Function Return Type .......... = Replace Undefined Data Types Only
	// Function Signature ............ = Replace When Same Parameter Count
	// Function Var Args ............. = Replace
	// Labels ........................ = Add
	// Plate Comment ................. = Add To Existing
	// Post Comment .................. = Add To Existing
	// Pre Comment ................... = Add To Existing
	// Repeatable Comment ............ = Add To Existing
	// Set Excluded Markup Items To Ignored ... = false
	// Set Incomplete Markup Items To Ignored . = false

	//  addPerson 00411860   FUN... 00411830    2 params
	//  call_Strncpy 0x00411ab0   FUN... 0x00411a90    3 params w/ matching types
	//  FUN_00411da0 00411da0   FUN... 00411d80    1 param & identical signature
	//  Gadget::use 00411570    FUN... 00411560

	public FunctionSignatureMarkupParameterName1Test() {
		super();
	}

	@Test
	public void testImportPriorityNameReplace_UserSrc_DefaultDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * SrcUserList, char * name)";
		String originalDestinationSignature = "void FUN_00411830(int * param_1, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_UserSrc_AnalysisDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcUserList", SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "DestAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * SrcUserList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_UserSrc_ImportDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcUserList", SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "DestImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * SrcUserList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestImportList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_UserSrc_UserDest_DoNotReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcUserList", SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "DestUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * SrcUserList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestUserList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_UserSrc_UserDest_ReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcUserList", SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "DestUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * SrcUserList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestUserList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, true);
	}

	@Test
	public void testImportPriorityNameReplace_ImportSrc_DefaultDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * SrcImportList, char * name)";
		String originalDestinationSignature = "void FUN_00411830(int * param_1, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_ImportSrc_AnalysisDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcImportList", SourceType.IMPORTED);
		setParameterName(destinationFunction, 0, "DestAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * SrcImportList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_ImportSrc_ImportDest_DoNotReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcImportList", SourceType.IMPORTED);
		setParameterName(destinationFunction, 0, "DestImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * SrcImportList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestImportList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_ImportSrc_ImportDest_ReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcImportList", SourceType.IMPORTED);
		setParameterName(destinationFunction, 0, "DestImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * SrcImportList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestImportList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, true);
	}

	@Test
	public void testImportPriorityNameReplace_ImportSrc_UserDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcImportList", SourceType.IMPORTED);
		setParameterName(destinationFunction, 0, "DestUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * SrcImportList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestUserList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * SrcImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_AnalysisSrc_DefaultDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * SrcAnalysisList, char * name)";
		String originalDestinationSignature = "void FUN_00411830(int * param_1, char * param_2)";
		String appliedDestinationSignature =
			"void FUN_00411830(int * SrcAnalysisList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_AnalysisSrc_AnalysisDest_DoNotReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcAnalysisList", SourceType.ANALYSIS);
		setParameterName(destinationFunction, 0, "DestAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * SrcAnalysisList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * param_2)";
		String appliedDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_AnalysisSrc_AnalysisDest_ReplaceSamePriority()
			throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcAnalysisList", SourceType.ANALYSIS);
		setParameterName(destinationFunction, 0, "DestAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * SrcAnalysisList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * param_2)";
		String appliedDestinationSignature =
			"void FUN_00411830(int * SrcAnalysisList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, true);
	}

	@Test
	public void testImportPriorityNameReplace_AnalysisSrc_ImportDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcAnalysisList", SourceType.ANALYSIS);
		setParameterName(destinationFunction, 0, "DestImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * SrcAnalysisList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestImportList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_AnalysisSrc_UserDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, "SrcAnalysisList", SourceType.ANALYSIS);
		setParameterName(destinationFunction, 0, "DestUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * SrcAnalysisList, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestUserList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_DefaultSrc_DefaultDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);

		String sourceSignature = "void addPerson(Person * * param_1, char * name)";
		String originalDestinationSignature = "void FUN_00411830(int * param_1, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * param_1, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_DefaultSrc_AnalysisDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterName(destinationFunction, 0, "DestAnalysisList", SourceType.ANALYSIS);

		String sourceSignature = "void addPerson(Person * * param_1, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * param_2)";
		String appliedDestinationSignature =
			"void FUN_00411830(int * DestAnalysisList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_DefaultSrc_ImportDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterName(destinationFunction, 0, "DestImportList", SourceType.IMPORTED);

		String sourceSignature = "void addPerson(Person * * param_1, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestImportList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestImportList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testImportPriorityNameReplace_DefaultSrc_UserDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterName(destinationFunction, 0, "DestUserList", SourceType.USER_DEFINED);

		String sourceSignature = "void addPerson(Person * * param_1, char * name)";
		String originalDestinationSignature =
			"void FUN_00411830(int * DestUserList, char * param_2)";
		String appliedDestinationSignature = "void FUN_00411830(int * DestUserList, char * name)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.PRIORITY_REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

	@Test
	public void testJustReplaceNameReplace() throws Exception {
		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		setParameterName(sourceFunction, 0, "Source_Dst", SourceType.ANALYSIS);
		setParameterName(sourceFunction, 1, "Source_Src", SourceType.USER_DEFINED);
		setParameterName(sourceFunction, 2, null, SourceType.DEFAULT);
		setParameterName(destinationFunction, 0, "Destination_Dst", SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 2, "Destination_MaxCount", SourceType.IMPORTED);

		checkSignatures(
			"void Call_strncpy_s(char * Source_Dst, char * Source_Src, rsize_t param_3)",
			"void FUN_00411a90(char * Destination_Dst, char * param_2, rsize_t Destination_MaxCount)");

		String sourceSignature =
			"void Call_strncpy_s(char * Source_Dst, char * Source_Src, rsize_t param_3)";
		String originalDestinationSignature =
			"void FUN_00411a90(char * Destination_Dst, char * param_2, rsize_t Destination_MaxCount)";
		String appliedDestinationSignature =
			"void FUN_00411a90(char * Source_Dst, char * Source_Src, rsize_t Destination_MaxCount)";
		SourcePriorityChoices parameterNamesChoice = SourcePriorityChoices.REPLACE;

		applyAndUnapplyParameterNameMarkup(sourceSignature, originalDestinationSignature,
			appliedDestinationSignature, parameterNamesChoice, IMPORT_PRIORITY_HIGHEST, false);
	}

//	===========================================================================

	private void applyAndUnapplyParameterNameMarkup(String sourceSignature,
			String originalDestinationSignature, String appliedDestinationSignature,
			SourcePriorityChoices parameterNamesChoice,
			HighestSourcePriorityChoices sourcePriorityChoice, boolean replaceSamePriorityNames) {
		checkSignatures(sourceSignature, originalDestinationSignature);

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, parameterNamesChoice);
		applyOptions.setEnum(HIGHEST_NAME_PRIORITY, sourcePriorityChoice);
		applyOptions.setBoolean(PARAMETER_NAMES_REPLACE_IF_SAME_PRIORITY, replaceSamePriorityNames);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkSignatures(sourceSignature, appliedDestinationSignature);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures(sourceSignature, originalDestinationSignature);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}
}
