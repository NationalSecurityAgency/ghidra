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
import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Test;

import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.symbol.SourceType;

public class FunctionSignatureMarkupTest extends AbstractFunctionSignatureMarkupTest {

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

	public FunctionSignatureMarkupTest() {
		super();
	}

@Test
    public void testDiffParamCount_ForceSignatureAndNamesWhenSameCount_3To2() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");
	}

@Test
    public void testDiffParamCount_ReplaceSignatureMarkupOnly_3To2() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t _MaxCount)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testDiff_ReplaceSignatureReplaceNames_3To2() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount, ...)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testApplyMarkup_ReplaceSignatureReplaceNames_2To3() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		removeParameter(sourceFunction, 2); // Remove the last parameter
		setVarArgs(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * _Dst, char * _Src)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3, ...)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testApplyMarkup_ReplaceSignature_2To2_ThisToThis_ReplaceComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.IMPORTED);

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1,
			"Destination Parameter 2 comment.\nSource Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

@Test
    public void testApplyMarkup_ReplaceSignature_2To2_ThisToThis_AppendComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.IMPORTED);

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1,
			"Destination Parameter 2 comment.\nSource Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

@Test
    public void testApplyMarkup_ReplaceSignature_2To2_ThisToThis_ExcludeComments() throws Exception {

		useMatch("0x00411570", "0x00411560");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.IMPORTED);

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * person)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

@Test
    public void testApplyMarkup_ReplaceSignature_2To2_ThisToThis_ExcludeNamesReplaceComments()
			throws Exception {

		useMatch("0x00411570", "0x00411560");

		// Check initial values
		checkSignatures("void use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.IMPORTED);

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(VAR_ARGS, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Get the Function Signature Markup
		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, Person * param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Source Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float use(Gadget * this, Person * person)",
			"void FUN_00411560(void * this, undefined4 param_1)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
//		checkMarkupStatus(parameterNamesMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}
}
