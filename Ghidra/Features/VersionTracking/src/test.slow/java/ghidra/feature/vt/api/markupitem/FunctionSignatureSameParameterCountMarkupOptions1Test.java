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

import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.SourceType;

public class FunctionSignatureSameParameterCountMarkupOptions1Test
		extends AbstractFunctionSignatureMarkupTest {

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

	//  addPerson 004011a0   FUN... 004011a0    2 params
	//  call_Strncpy 00401300   FUN... 00401310    3 params w/ matching types
	//  Canary_Tester_... 0040131c   FUN... 0040132c    1 param & identical signature

	//  addPerson 00411860   FUN... 00411830    2 params
	//  call_Strncpy 0x00411ab0   FUN... 0x00411a90    3 params w/ matching types
	//  FUN_00411da0 00411da0   FUN... 00411d80    1 param & identical signature
	//  Gadget::use 00411570    FUN... 00411560

	@Test
	public void testSameParamCount_ReplaceSignature() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");
		SourceType[] sourceTypes = getParameterSourceTypes(sourceFunction);
		SourceType[] originalDestinationTypes = getParameterSourceTypes(destinationFunction);

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Signature Markup
		List<VTMarkupItem> signatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, signatureMarkupItems.size());
		applyFunctionSignatureMarkup(signatureMarkupItems);

		// Verify the markup was applied.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkDestinationParameterNameSourceTypes(sourceTypes);

		unapplyFunctionSignatureMarkup(signatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkDestinationParameterNameSourceTypes(originalDestinationTypes);

	}

	@Test
	public void testSameParamCount_ReplaceSignature_ExcludeVarArgs() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_VarArgsNoVarArgs() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_NoVarArgsVarArgs() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_BothNoVarArgs() {

		useMatch("0x00411ab0", "0x00411a90");

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_BothWithVarArgs() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		setVarArgs(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ExcludeParameterComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

	@Test
	public void testSameParamCount_ReplaceSignature_OverwriteParameterComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Source Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

	@Test
	public void testSameParamCount_ReplaceSignature_AppendToParameterComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1,
			"Destination Parameter 2 comment.\nSource Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ExcludeParameterDataTypes() throws Exception {

		useMatch("0x00411860", "0x00411830");

		setVarArgs(sourceFunction, true);
		setParameterDataType(destinationFunction, 1, new DWordDataType(), SourceType.USER_DEFINED);

		checkSignatures("void addPerson(Person * * list, char * name, ...)",
			"void FUN_00411830(int * param_1, dword param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name, ...)",
			"void FUN_00411830(int * list, dword name, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name, ...)",
			"void FUN_00411830(int * param_1, dword param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	// TODO
	// TODO
	// TODO this address needs to be updated: I think it is 00411da0/00411d80
	// TODO
	// TODO

	@Test
	public void testSameParamCount_ReplaceSignature_ReplaceNamesMatching_NeitherInline() {

		useMatch("0x00411da0", "0x00411d80");

		setInline(sourceFunction, false);
		setInline(destinationFunction, false);

		checkSignatures("undefined FUN_00411da0(undefined1 param_1)",
			"undefined FUN_00411d80(undefined1 param_1)");
		assertFalse(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.SAME);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ReplaceNamesMatchingBoth_Inline() {

		useMatch("0x00411da0", "0x00411d80");

		setInline(sourceFunction, true);
		setInline(destinationFunction, true);

		checkSignatures("undefined FUN_00411da0(undefined1 param_1)",
			"undefined FUN_00411d80(undefined1 param_1)");
		assertTrue(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.SAME);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ExcludeNames() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setParameterName(sourceFunction, 0, "MyDest", SourceType.IMPORTED);
		setParameterName(destinationFunction, 2, "count", SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ReplaceDefaultNamesOnly() throws Exception {
		useMatch("0x00411ab0", "0x00411a90");

		setParameterName(sourceFunction, 0, "MyDest", SourceType.IMPORTED);
		setParameterName(destinationFunction, 2, "count", SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * MyDest, char * _Src, rsize_t count)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameParamCount_ReplaceSignature_ReplaceNames() throws Exception {
		useMatch("0x00411ab0", "0x00411a90");

		setParameterName(sourceFunction, 0, "MyDest", SourceType.IMPORTED);
		setParameterName(destinationFunction, 2, "count", SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * MyDest, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * MyDest, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t count)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}
}
