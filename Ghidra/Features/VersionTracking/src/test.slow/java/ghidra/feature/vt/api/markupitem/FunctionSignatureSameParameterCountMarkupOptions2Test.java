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
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class FunctionSignatureSameParameterCountMarkupOptions2Test
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
	public void testSameParamCount_ExcludeSignature() throws Exception {

		useMatch("0x00411ab0", "0x00411a90");
		SourceType[] originalDestinationTypes = getParameterSourceTypes(destinationFunction);

		// Check initial values
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.EXCLUDE);

		checkMatchStatus(VTAssociationStatus.AVAILABLE);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Test Apply of Signature Markup
		List<VTMarkupItem> signatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, signatureMarkupItems.size());
		applyFunctionSignatureMarkup(signatureMarkupItems);

		// Verify the markup was not applied.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		checkMatchStatus(VTAssociationStatus.ACCEPTED);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkDestinationParameterNameSourceTypes(originalDestinationTypes);
	}

	@Test
	public void testSameParamCount_ExcludeInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, true);
		setInline(destinationFunction, false);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(true, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkInlineFlags(true, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(true, false);
	}

	@Test
	public void testSameParamCount_NotInlineNotInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, false);
		setInline(destinationFunction, false);

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
		checkInlineFlags(false, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkInlineFlags(false, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(false, false);
	}

	@Test
	public void testSameParamCount_InlineInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, true);
		setInline(destinationFunction, true);

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
		checkInlineFlags(true, true);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkInlineFlags(true, true);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(true, true);
	}

	@Test
	public void testSameParamCount_InlineNotInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, true);
		setInline(destinationFunction, false);

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
		checkInlineFlags(true, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkInlineFlags(true, true);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(true, false);
	}

	@Test
	public void testSameParamCount_NotInlineInline() {

		useMatch("0x00411ab0", "0x00411a90");

		setInline(sourceFunction, false);
		setInline(destinationFunction, true);

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
		checkInlineFlags(false, true);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkInlineFlags(false, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkInlineFlags(false, true);
	}

	@Test
	public void testSameParamCount_ExcludeNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, true);
		setNoReturn(destinationFunction, false);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(true, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkNoReturnFlags(true, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(true, false);
	}

	@Test
	public void testSameParamCount_NotANoReturnNotANoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, false);
		setNoReturn(destinationFunction, false);

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
		checkNoReturnFlags(false, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkNoReturnFlags(false, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(false, false);
	}

	@Test
	public void testSameParamCount_NoReturnNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, true);
		setNoReturn(destinationFunction, true);

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
		checkNoReturnFlags(true, true);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkNoReturnFlags(true, true);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(true, true);
	}

	@Test
	public void testSameParamCount_NoReturnNotANoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, true);
		setNoReturn(destinationFunction, false);

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
		checkNoReturnFlags(true, false);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkNoReturnFlags(true, true);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(true, false);
	}

	@Test
	public void testSameParamCount_NotANoReturnNoReturn() {

		useMatch("0x00411ab0", "0x00411a90");

		setNoReturn(sourceFunction, false);
		setNoReturn(destinationFunction, true);

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
		checkNoReturnFlags(false, true);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * _Dst, char * _Src, rsize_t _MaxCount)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);
		checkNoReturnFlags(false, false);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void Call_strncpy_s(char * _Dst, char * _Src, rsize_t _MaxCount)",
			"void FUN_00411a90(char * param_1, char * param_2, rsize_t param_3)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
		checkNoReturnFlags(false, true);
	}

	@Test
	public void testSameLanguageReplaceCallingConventionBothSpecified() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setCallingConvention(sourceFunction, "__cdecl"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall
		setCallingConvention(destinationFunction, "__stdcall"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", "__stdcall");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__cdecl", "__cdecl");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", "__stdcall");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameLanguageReplaceCallingConventionSameSpecified() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setCallingConvention(sourceFunction, "__cdecl"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall
		setCallingConvention(destinationFunction, "__cdecl"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", "__cdecl");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__cdecl", "__cdecl");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", "__cdecl");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameLanguageReplaceCallingConventionNoSrcButDestSpecified() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setCallingConvention(sourceFunction, Function.UNKNOWN_CALLING_CONVENTION_STRING); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall
		setCallingConvention(destinationFunction, "__stdcall"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING, "__stdcall");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING,
			Function.UNKNOWN_CALLING_CONVENTION_STRING);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention(Function.UNKNOWN_CALLING_CONVENTION_STRING, "__stdcall");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testSameLanguageReplaceCallingConventionSrcSpecifiedButNoDest() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setCallingConvention(sourceFunction, "__cdecl"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall
		setCallingConvention(destinationFunction, Function.UNKNOWN_CALLING_CONVENTION_STRING); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", Function.UNKNOWN_CALLING_CONVENTION_STRING);

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__cdecl", "__cdecl");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__cdecl", Function.UNKNOWN_CALLING_CONVENTION_STRING);
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

}
