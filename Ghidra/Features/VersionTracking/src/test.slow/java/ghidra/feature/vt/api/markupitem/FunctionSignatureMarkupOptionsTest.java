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
import ghidra.framework.store.LockException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitorAdapter;

public class FunctionSignatureMarkupOptionsTest extends AbstractFunctionSignatureMarkupTest {

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

	public FunctionSignatureMarkupOptionsTest() {
		super();
	}

@Test
    public void testExcludeCallingConvention() throws Exception {
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
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__cdecl", "__stdcall");
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
    public void testNameMatchReplaceCallingConventionBothSpecified() throws Exception {
		setLanguage(destinationProgram, "Toy:LE:32:default", "default");

		useMatch("0x00411860", "0x00411830");

		setCallingConvention(sourceFunction, "__stdcall"); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall
		setCallingConvention(destinationFunction, Function.UNKNOWN_CALLING_CONVENTION_STRING); // unknown, default, __stdcall, __cdecl, __fastcall, __thiscall

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__stdcall", Function.UNKNOWN_CALLING_CONVENTION_STRING);

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__stdcall", "__stdcall");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallingConvention("__stdcall", Function.UNKNOWN_CALLING_CONVENTION_STRING);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testNameMatchNotFoundCallingConventionBothSpecified() throws Exception {
		setLanguage(destinationProgram, "Toy:LE:32:default", "default");

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
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallingConvention("__cdecl", Function.UNKNOWN_CALLING_CONVENTION_STRING);
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

@Test
    public void testReplaceSrcCallFixupNoDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		setCallFixup(sourceFunction, "SEH_prolog4");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", null);

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup("SEH_prolog4", "SEH_prolog4");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", null);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceNoSrcCallFixupDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		setCallFixup(destinationFunction, "SEH_prolog4");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup(null, "SEH_prolog4");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup(null, null);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup(null, "SEH_prolog4");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceSrcCallFixupSameDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		setCallFixup(sourceFunction, "SEH_prolog4");
		setCallFixup(destinationFunction, "SEH_prolog4");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "SEH_prolog4");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup("SEH_prolog4", "SEH_prolog4");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "SEH_prolog4");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceSrcCallFixupDifferentDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		setCallFixup(sourceFunction, "SEH_prolog4");
		setCallFixup(destinationFunction, "EH_prolog");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "EH_prolog");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup("SEH_prolog4", "SEH_prolog4");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "EH_prolog");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testExcludeSrcCallFixupDifferentDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		setCallFixup(sourceFunction, "SEH_prolog4");
		setCallFixup(destinationFunction, "EH_prolog");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "EH_prolog");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup("SEH_prolog4", "EH_prolog");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup("SEH_prolog4", "EH_prolog");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceNoSrcCallFixupNoDestCallFixup() {
		useMatch("0x00411860", "0x00411830");

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup(null, null);

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(CALL_FIXUP, ReplaceChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		checkCallFixup(null, null);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("void addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		checkCallFixup(null, null);
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testExcludeReturnType() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.USER_DEFINED);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("float addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceDefinedReturnTypeWithDefined() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setReturnType(destinationFunction, new DWordDataType(), SourceType.USER_DEFINED);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"float FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("float addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceUndefinedReturnTypeWithDefinedForReplace() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.USER_DEFINED);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"float FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("float addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testDontReplaceDefinedReturnTypeWithDefinedForUndefinedOnly() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setReturnType(destinationFunction, new DWordDataType(), SourceType.USER_DEFINED);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("float addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceUndefinedReturnTypeWithDefinedForUndefinedOnly() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setReturnType(destinationFunction, new Undefined2DataType(), SourceType.USER_DEFINED);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"undefined2 FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("float addPerson(Person * * list, char * name)",
			"float FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("float addPerson(Person * * list, char * name)",
			"undefined2 FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testReplaceDefaultReturnTypeWithUndefined() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new Undefined4DataType(), SourceType.USER_DEFINED);

		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"void FUN_00411830(int * param_1, char * param_2)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);
	}

@Test
    public void testDontReplaceDefinedReturnTypeWithUndefined() throws Exception {
		useMatch("0x00411860", "0x00411830");

		setReturnType(sourceFunction, new Undefined4DataType(), SourceType.USER_DEFINED);
		setReturnType(destinationFunction, new DWordDataType(), SourceType.USER_DEFINED);

		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = vtTestEnv.getVTController().getOptions();
		setApplyMarkupOptionsToDefaults(applyOptions);
		// Now change the options where we don't want the default value.
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		// Function Signature Markup
		List<VTMarkupItem> functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, true);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.UNAPPLIED);

		applyFunctionSignatureMarkup(functionSignatureMarkupItems);

		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * list, char * name)");
		functionSignatureMarkupItems =
			getSpecificTypeOfMarkup(FunctionSignatureMarkupType.class, testMatch, false);
		assertEquals(1, functionSignatureMarkupItems.size());
		checkMarkupStatus(functionSignatureMarkupItems, VTMarkupItemStatus.REPLACED);

		unapplyFunctionSignatureMarkup(functionSignatureMarkupItems);

		// Verify the unapply.
		checkSignatures("undefined4 addPerson(Person * * list, char * name)",
			"dword FUN_00411830(int * param_1, char * param_2)");
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

private void setLanguage(Program program, String languageID, String compilerSpecName)
			throws IllegalStateException, LockException, IncompatibleLanguageException,
			LanguageNotFoundException {
		int transaction = -1;
		try {
			transaction =
				program.startTransaction("Test - Setting Language: " + languageID.toString());
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			Language language = languageService.getLanguage(new LanguageID(languageID));
			List<CompilerSpecDescription> compatibleCompilerSpecDescriptions =
				language.getCompatibleCompilerSpecDescriptions();
			CompilerSpecID compilerSpecID = null;
			for (CompilerSpecDescription compilerSpecDescription : compatibleCompilerSpecDescriptions) {
				if (compilerSpecDescription.getCompilerSpecName().equals(compilerSpecName)) {
					compilerSpecID = compilerSpecDescription.getCompilerSpecID();
				}
			}
			assertNotNull(compilerSpecID);
			program.setLanguage(language, compilerSpecID, true, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}
}
