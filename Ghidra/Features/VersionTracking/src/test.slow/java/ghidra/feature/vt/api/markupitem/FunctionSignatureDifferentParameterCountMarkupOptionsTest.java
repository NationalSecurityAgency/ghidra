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
import ghidra.feature.vt.api.markuptype.FunctionNameMarkupType;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.data.*;
import ghidra.program.model.symbol.SourceType;

public class FunctionSignatureDifferentParameterCountMarkupOptionsTest
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
	public void testDiffParamCount_ReplaceDefaultFunctionName() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_DEFAULT_ONLY);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionNameMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void Call_strncpy_s(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, false);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionNameMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceFunctionNameAlways() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);

		// Get the Function Name Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionNameMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void Call_strncpy_s(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, false);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionNameMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceDefaultFunctionName_Defined() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setFunctionName(destinationFunction, "otherStrncpy", SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void otherStrncpy(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_DEFAULT_ONLY);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionNameMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void otherStrncpy(char * param_1, char * param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, false);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		unapplyFunctionSignatureMarkup(functionNameMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void otherStrncpy(char * param_1, char * param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceFunctionNameAlways_Defined() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_NAME, FunctionNameChoices.REPLACE_ALWAYS);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionNameMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void Call_strncpy_s(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, false);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionNameMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");
		functionNameMarkupItems =
			getSpecificTypeOfMarkup(FunctionNameMarkupType.class, testMatch, true);
		assertEquals(1, functionNameMarkupItems.size());
		checkMarkupStatus(functionNameMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_DontReplaceSignature() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");
	}

	@Test
	public void testDiffParamCount_ReplaceSignature() {
		//
		// We are testing that a parameter signature that has a different number of parameters
		// between the source and destination will toggle default addresses as the parameter 
		// signature is applied and reverted.  This is here due to a bug in our caching that 
		// did not update our addresses.
		//

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
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
			"void FUN_00411a90(char * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_Replace3To2Signature_OverwriteParameterComments()
			throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		removeParameter(destinationFunction, 2); // Remove the last parameter

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");
		setParameterComment(sourceFunction, 2, "Source Parameter 3 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(sourceFunction, 2, "Source Parameter 3 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
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
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(sourceFunction, 2, "Source Parameter 3 comment.");

		checkParameterComments(destinationFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(destinationFunction, 2, "Source Parameter 3 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");
		checkParameterComments(sourceFunction, 2, "Source Parameter 3 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
	}

	@Test
	public void testDiffParamCount_Replace2To3Signature_OverwriteParameterComments()
			throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		removeParameter(sourceFunction, 2); // Remove the last parameter

		setParameterComment(sourceFunction, 1, "Source Parameter 2 comment.");

		setParameterComment(destinationFunction, 1, "Destination Parameter 2 comment.");
		setParameterComment(destinationFunction, 2, "Destination Parameter 3 comment.");

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
		checkParameterComments(destinationFunction, 2, "Destination Parameter 3 comment.");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
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
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * _Dst, char * _Src)");
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Source Parameter 2 comment.");

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		checkParameterComments(sourceFunction, 1, "Source Parameter 2 comment.");

		checkParameterComments(destinationFunction, 1, "Destination Parameter 2 comment.");
		checkParameterComments(destinationFunction, 2, "Destination Parameter 3 comment.");
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceAllDataTypes() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 0, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);

		// Get the Function Signature Markup
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
			"void FUN_00411a90(float param_1, undefined4 param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceSignature_DontReplaceWithLessDefinedDataTypes()
			throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		setParameterDataType(sourceFunction, 0, new Undefined4DataType(), SourceType.USER_DEFINED);
		setParameterDataType(sourceFunction, 1, DataType.DEFAULT, SourceType.DEFAULT);
		setParameterDataType(sourceFunction, 2, new Undefined2DataType(), SourceType.DEFAULT);
		setParameterDataType(destinationFunction, 0, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 2, new Undefined1DataType(),
			SourceType.USER_DEFINED);

		checkSignatures(
			"void Call_strncpy_s(undefined4 _Dst, undefined _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2, undefined1 param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures(
			"void Call_strncpy_s(undefined4 _Dst, undefined _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float _Dst, undefined4 _Src, undefined2 _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures(
			"void Call_strncpy_s(undefined4 _Dst, undefined _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2, undefined1 param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceUndefinedDataTypes() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		setParameterDataType(sourceFunction, 2, new Undefined2DataType(), SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 0, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 2, DataType.DEFAULT, SourceType.DEFAULT);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2, undefined param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float _Dst, char * _Src, undefined2 _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, undefined2 _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2, undefined param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceDefaultWithUndefinedDataType()
			throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 0, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(float _Dst, char * _Src, rsize_t _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(float param_1, undefined4 param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ExcludeParameterNames() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t _MaxCount, ...)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignatureReplaceParameterNames() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter
		setParameterDataType(destinationFunction, 1, new Undefined4DataType(),
			SourceType.USER_DEFINED);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, undefined4 param_2)");

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

		// Get the Function Signature Markup
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
			"void FUN_00411a90(char * param_1, undefined4 param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNames() {

		useMatch("0x00411ab0", "0x00411a90");

		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 2); // Remove the last parameter

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount, ...)",
			"void FUN_00411a90(char * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);

		// Test Apply of Signature Markup
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
			"void FUN_00411a90(char * param_1, char * param_2)");
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
	public void testDiffParamCount_ReplaceSignature_ReplaceNamesUsingImportPriority()
			throws Exception {
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
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.PRIORITY_REPLACE);
		applyOptions.setEnum(HIGHEST_NAME_PRIORITY,
			HighestSourcePriorityChoices.IMPORT_PRIORITY_HIGHEST);

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
	public void testDiffParamCount_ReplaceSignature_ReplaceNames_ExcludeInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignatureReplaceNames_ExcludeOtherInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNames_SetInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNames_UnsetInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertFalse(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.isInline());
		assertTrue(destinationFunction.isInline());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignatureReplaceNamesExcludeNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		assertTrue(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNamesExcludeOther_NoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		assertFalse(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNames_SetNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		// Test Apply of Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		assertTrue(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertTrue(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());

		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testDiffParamCount_ReplaceSignature_ReplaceNames_UnsetNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(destinationFunction, true);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);

		// Get the Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		assertFalse(sourceFunction.hasNoReturn());
		assertFalse(destinationFunction.hasNoReturn());
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		assertFalse(sourceFunction.hasNoReturn());
		assertTrue(destinationFunction.hasNoReturn());

		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}
}
