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
package ghidra.features.codecompare.decompile;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.decompiler.ClangToken;
import ghidra.features.codecompare.plugin.FunctionComparisonProvider;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Duo.Side;

public class DualDecompilerActionTest extends AbstractDualDecompilerTest {
	private FunctionComparisonProvider provider = null;

	private Program progDemangler24Debug;
	private Function funcDemangler24DebugMain;
	private Function funcDemangler24DebugCplusDemangle;
	private static final long DEMANGLER_24_DEBUG_MAIN_OFFSET = 0x414835;
	private static final long DEMANGLER_24_DEBUG_CPLUS_DEMANGLE_OFFSET = 0x40c01b;
	private static final long DEMANGLER_24_DEBUG_INTERNAL_CPLUS_DEMANGLE_OFFSET = 0x40c987;
	private static final String DEMANGLER_24_DEBUG_PROG_NAME =
		"CodeCompare/demangler_gnu_v2_24_fulldebug";

	private Program progDemangler24Stripped;
	private Function funcDemangler24StrippedMain;
	private Function funcDemangler24StrippedCplusDemangle;
	private static final long DEMANGLER_24_STRIPPED_MAIN_OFFSET = 0x414835;
	private static final long DEMANGLER_24_STRIPPED_CPLUS_DEMANGLE_OFFSET = 0x40c01b;
	private static final long DEMANGLER_24_STRIPPED_INTERNAL_CPLUS_DEMANGLE_OFFSET = 0x40c987;
	private static final String DEMANGLER_24_STRIPPED_PROG_NAME =
		"CodeCompare/demangler_gnu_v2_24_stripped";

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		progDemangler24Debug = env.getProgram(DEMANGLER_24_DEBUG_PROG_NAME);
		progDemangler24Stripped = env.getProgram(DEMANGLER_24_STRIPPED_PROG_NAME);

		assertNotNull(progDemangler24Debug);
		assertNotNull(progDemangler24Stripped);

		funcDemangler24DebugMain =
			getFunctionFromOffset(progDemangler24Debug, DEMANGLER_24_DEBUG_MAIN_OFFSET);
		funcDemangler24DebugCplusDemangle =
			getFunctionFromOffset(progDemangler24Debug, DEMANGLER_24_DEBUG_CPLUS_DEMANGLE_OFFSET);
		funcDemangler24StrippedMain =
			getFunctionFromOffset(progDemangler24Stripped, DEMANGLER_24_STRIPPED_MAIN_OFFSET);
		funcDemangler24StrippedCplusDemangle =
			getFunctionFromOffset(progDemangler24Stripped,
				DEMANGLER_24_STRIPPED_CPLUS_DEMANGLE_OFFSET);

		assertNotNull(funcDemangler24DebugMain);
		assertNotNull(funcDemangler24DebugCplusDemangle);
		assertNotNull(funcDemangler24StrippedMain);
		assertNotNull(funcDemangler24StrippedCplusDemangle);

		showTool(fcPlugin.getTool());
		env.open(progDemangler24Debug);
		env.open(progDemangler24Stripped);
	}

	@Override
	@After
	public void tearDown() throws Exception {
		super.tearDown();
	}

	/*
	 * Comparisons of these functions are used in the next few tests
	
	  
	 Decomp of 'main' in 'demangler_gnu_v2_24_fulldebug':
		 1|
		 2| int main(int argc,char **argv)
		 3|
		 4| {
		 5|   char *pcVar1;
		 6|   char **argv_local;
		 7|   int argc_local;
		 8|   char *options;
		 9|   char *demangler;
		10|   int skip_first;
		11|   int i;
		12|   char *valid_symbols;
		13|   int c;
		14|  
		15|   demangler = (char *)0x0;
		16|   options = (char *)0x0;
		17|   program_name = *argv;
		18|   strip_underscore = prepends_underscore;
		19|   argv_local = argv;
		20|   argc_local = argc;
		21|   expandargv(&argc_local,&argv_local);
		...
		
		
	 Decomp of 'FUN_00414835' (main) in 'demangler_gnu_v2_41_stripped':
	 	 1|
	 	 2| undefined8 FUN_00414835(int param_1,undefined8 *param_2)
		 3|
		 4| {
		 5|   char *pcVar1;
		 6|   undefined8 *local_48;
		 7|   int local_3c [3];
		 8|   undefined8 local_30;
		 9|   undefined8 local_28;
		10|   int local_20;
		11|   int local_1c;
		12|   char *local_18;
		13|   uint local_c;
		14|  
		15|   local_28 = 0;
		16|   local_30 = 0;
		17|   DAT_004252e0 = *param_2;
		18|   DAT_0041d220 = DAT_00425240;
		19|   local_48 = param_2;
		20|   local_3c[0] = param_1;
		21|   FUN_00401a2d(local_3c,&local_48);
		...
	
	
	 Decomp of 'FUN_0040c01b' (cplus_demangle) in 'demangler_gnu_v2_24_stripped':
		 1|
		 2| long FUN_0040c01b(undefined8 param_1,uint param_2)
		 3|
		 4| {
		 5|   long lVar1;
		 6|   uint local_88 [30];
		 7|   long local_10;
		 8|  
		 9|   if (DAT_0041d150 == 0xffffffff) {
		10|     local_10 = FUN_0040b419(param_1);
		11|   }
		12|   else {
		13|     memset(local_88,0,0x70);
		14|     local_88[0] = param_2;
		15|     if ((param_2 & 0xff04) == 0) {
		16|       local_88[0] = DAT_0041d150 & 0xff04 | param_2;
		17|     }
		...
	*/

	@Test
	public void testLocalNameTransferAction() throws RuntimeException {
		final String actionName = ApplyLocalNameFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedCplusDemangle);
		DockingActionIf localNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(localNameTransferAction);

		line = 15;
		col = 0;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated local variable token 'demangler'
		// Ensure the local variable name transfer action is not active
		assertEquals("demangler", currentToken.getText());
		assertNotEnabled(localNameTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedMain);
		// Recreated provider, need to get new handle on action
		localNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(localNameTransferAction);

		line = 15;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated constant token '0'.
		// Ensure the local variable name transfer action is not active
		assertEquals("0", currentToken.getText());
		assertNotEnabled(localNameTransferAction, getProviderContext());

		line = 17;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_004252e0'
		// Ensure the local variable name transfer action is not active
		assertEquals("DAT_004252e0", currentToken.getText());
		assertNotEnabled(localNameTransferAction, getProviderContext());

		line = 15;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_28'
		// Ensure the local variable name transfer action is active and working
		assertEquals("local_28", currentToken.getText());
		assertEnabled(localNameTransferAction, getProviderContext());

		performAction(localNameTransferAction);
		waitForDecompile(correlatedPanel);
		currentToken = getCurrentToken(correlatedPanel, Side.RIGHT);
		assertEquals("demangler", currentToken.getText());
	}

	@Test
	public void testGlobalNameTransferAction() throws RuntimeException {
		final String actionName = ApplyGlobalNameFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedCplusDemangle);
		DockingActionIf globalNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(globalNameTransferAction);

		line = 17;
		col = 0;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated global variable token 'program_name'
		// Ensure the global variable name transfer action is not active
		assertEquals("program_name", currentToken.getText());
		assertNotEnabled(globalNameTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedMain);
		// Recreated provider, need to get new handle on action
		globalNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(globalNameTransferAction);

		line = 15;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated constant token '0'.
		// Ensure the global variable name transfer action is not active
		assertEquals("0", currentToken.getText());
		assertNotEnabled(globalNameTransferAction, getProviderContext());

		line = 15;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_28'
		// Ensure the global variable name transfer action is not active
		assertEquals("local_28", currentToken.getText());
		assertNotEnabled(globalNameTransferAction, getProviderContext());

		line = 17;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_004252e0'
		// Ensure the global variable name transfer action is active and working
		assertEquals("DAT_004252e0", currentToken.getText());
		assertEnabled(globalNameTransferAction, getProviderContext());
		performAction(globalNameTransferAction);
		waitForDecompile(correlatedPanel);
		currentToken = getCurrentToken(correlatedPanel, Side.RIGHT);
		assertEquals("program_name", currentToken.getText());
	}

	@Test
	public void testVariableTypeTransferAction() throws RuntimeException {
		final String actionName = ApplyVariableTypeFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedCplusDemangle);
		DockingActionIf typeTransferAction = getLocalAction(provider, actionName);
		assertNotNull(typeTransferAction);

		line = 15;
		col = 0;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated local variable token 'demangler'
		// Ensure the variable type transfer action is not active
		assertEquals("demangler", currentToken.getText());
		assertNotEnabled(typeTransferAction, getProviderContext());

		line = 17;
		col = 0;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated global variable token 'program_name'
		// Ensure the variable type transfer action is not active
		assertEquals("program_name", currentToken.getText());
		assertNotEnabled(typeTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugMain, funcDemangler24StrippedMain);
		// Recreated provider, need to get new handle on action
		typeTransferAction = getLocalAction(provider, actionName);
		assertNotNull(typeTransferAction);

		line = 15;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated constant token '0'.
		// Ensure the variable type transfer action is not active
		assertEquals("0", currentToken.getText());
		assertNotEnabled(typeTransferAction, getProviderContext());

		line = 15;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_28'
		// Ensure the variable type transfer action is active and works on local variable
		assertEquals("local_28", currentToken.getText());
		assertEnabled(typeTransferAction, getProviderContext());
		performAction(typeTransferAction);
		waitForDecompile(correlatedPanel);
		// Check that 'local_28 = 0;' has become 'local_28 = (char *)0x0;
		col = 12;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("char", currentToken.getText());
		col = 17;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("*", currentToken.getText());

		line = 17;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_004252e0'
		// Ensure the global variable name transfer action is active and working
		assertEquals("DAT_004252e0", currentToken.getText());
		assertEnabled(typeTransferAction, getProviderContext());
		performAction(typeTransferAction);
		waitForDecompile(correlatedPanel);
		// Check that 'DAT_004252e0 = *param_2;' has become 'PTR_004252e0 = (char *)*param_2;'
		currentToken = getCurrentToken(correlatedPanel, Side.RIGHT);
		assertEquals("PTR_004252e0", currentToken.getText());
		col = 16;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("char", currentToken.getText());
		col = 21;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("*", currentToken.getText());
	}

	/**
	 * The callee and struct type tests use the decomp of the following functions. We care about
	 * the work_stuff struct and the call to 'internal_cplus_demangle' / 'FUN_0040c987', which has
	 * debug signature: 	char * internal_cplus_demangle(work_stuff *work, char *mangled)
	 * stripped signature: 	undefined8 FUN_0040c987(uint *param_1,char *param_2):
	 
	 Decomp of 'cplus_demangle' in 'demangler_gnu_v2_24_fulldebug':
	  	 1|
	  	 2| char * cplus_demangle(char *mangled,int options)
		 3|
		 4| {
		 5|   char *pcVar1;
		 6|   int options_local;
		 7|   char *mangled_local;
		 8|   work_stuff work [1];
		 9|   char *ret;
		10|  
		11|   if (current_demangling_style == no_demangling) {
		12|     pcVar1 = xstrdup(mangled);
		13|   }
		14|   else {
		15|     memset(work,0,0x70);
		16|     work[0].options = options;
		17|     if ((options & 0xff04U) == 0) {
		18|       work[0].options =
		19|            current_demangling_style &
		20|            (gnat_demangling|gnu_v3_demangling|edg_demangling|hp_demangling|arm_demangling|
		21|             lucid_demangling|gnu_demangling|auto_demangling|java_demangling) | options;
		22|     }
		23|     if (((((work[0].options & 0x4000U) == 0) && ((work[0].options & 0x100U) == 0)) ||
		24|         ((pcVar1 = cplus_demangle_v3(mangled,work[0].options), pcVar1 == (char *)0x0 &&
		25|          ((work[0].options & 0x4000U) == 0)))) &&
		26|        (((work[0].options & 4U) == 0 || (pcVar1 = java_demangle_v3(mangled), pcVar1 == (char *)0x0))
		27|        )) {
		28|       if ((work[0].options & 0x8000U) == 0) {
		29|         pcVar1 = internal_cplus_demangle(work,mangled);
		30|         squangle_mop_up(work);
		31|       }
		32|       else {
		33|         pcVar1 = ada_demangle(mangled,options);
		34|       }
		35|     }
		36|   }
		37|   return pcVar1;
		38| }
		
		
	 Decomp of 'FUN_0040c01b' (cplus_demangle) in 'demangler_gnu_v2_24_stripped':
		 1|
		 2| long FUN_0040c01b(undefined8 param_1,uint param_2)
		 3|
		 4| {
		 5|   long lVar1;
		 6|   uint local_88 [30];
		 7|   long local_10;
		 8|
		 9|   if (DAT_0041d150 == 0xffffffff) {
		10|     local_10 = FUN_0040b419(param_1);
		11|   }
		12|   else {
		13|     memset(local_88,0,0x70);
		14|     local_88[0] = param_2;
		15|     if ((param_2 & 0xff04) == 0) {
		16|       local_88[0] = DAT_0041d150 & 0xff04 | param_2;
		17|     }
		18|     if (((((local_88[0] & 0x4000) == 0) && (lVar1 = local_10, (local_88[0] & 0x100) == 0)) ||
		19|         ((local_10 = FUN_0040a8cc(param_1,local_88[0]), local_10 == 0 &&
		20|          (lVar1 = 0, (local_88[0] & 0x4000) == 0)))) &&
		21|        ((local_10 = lVar1, (local_88[0] & 4) == 0 ||
		22|         (local_10 = FUN_0040a922(param_1), local_10 == 0)))) {
		23|       if ((local_88[0] & 0x8000) == 0) {
		24|         local_10 = FUN_0040c987(local_88,param_1);
		25|         FUN_0040cb6c(local_88);
		26|       }
		27|       else {
		28|         local_10 = FUN_0040c154(param_1,param_2);
		29|       }
		30|     }
		31|   }
		32|   return local_10;
		33| }
	 */

	@Test
	public void testFullStructTypeTransferAction() throws RuntimeException {
		final String actionName = ApplyVariableTypeFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedCplusDemangle);
		DockingActionIf typeTransferAction = getLocalAction(provider, actionName);
		assertNotNull(typeTransferAction);

		line = 14;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_88'.
		// Ensure the variable type transfer action is active, and 
		assertEquals("local_88", currentToken.getText());
		assertEnabled(typeTransferAction, getProviderContext());
		performAction(typeTransferAction);
		waitForDecompile(correlatedPanel);

		// Sanity check: options field exists
		line = 13;
		col = 12;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("options", currentToken.getText());

		// Check that the work_stuff struct is fully in the data type manager
		ProgramBasedDataTypeManager debugDtm = progDemangler24Debug.getDataTypeManager();
		Structure debugStructure =
			(Structure) debugDtm.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));
		assertNotNull(debugStructure);

		ProgramBasedDataTypeManager strippedDtm = progDemangler24Stripped.getDataTypeManager();
		Structure strippedStructure = (Structure) strippedDtm
				.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));
		assertNotNull(strippedStructure);

		assertEquals(debugStructure.getNumComponents(), strippedStructure.getNumComponents());
	}

	@Test
	public void testSkeletonStructTypeTransferAction() throws RuntimeException {
		final String actionName = ApplyEmptyVariableTypeFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedCplusDemangle);
		DockingActionIf typeTransferAction = getLocalAction(provider, actionName);
		assertNotNull(typeTransferAction);

		line = 14;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);

		// Cursor is now on correlated local variable token 'local_88'.
		// Ensure the variable type transfer action is active, and 
		assertEquals("local_88", currentToken.getText());
		assertEnabled(typeTransferAction, getProviderContext());
		performAction(typeTransferAction);
		waitForDecompile(correlatedPanel);

		// Sanity check: variable declaration is retyped
		line = 6;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("work_stuff", currentToken.getText());

		// Check that an empty struct is in the data type manager
		ProgramBasedDataTypeManager dtm = progDemangler24Stripped.getDataTypeManager();
		Structure structure =
			(Structure) dtm.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));

		assertNotNull(structure);
		assertTrue(structure.isNotYetDefined());
		assertTrue(structure.isZeroLength());
		assertEquals(0, structure.getNumComponents());
	}

	@Test
	public void testCalleeNameTransferAction() throws RuntimeException {
		final String actionName = ApplyCalleeFunctionNameFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedMain);
		DockingActionIf calleeNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeNameTransferAction);

		line = 12;
		col = 9;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated callee token 'xstrdup'
		// Ensure the callee name transfer action is not active
		assertEquals("xstrdup", currentToken.getText());
		assertNotEnabled(calleeNameTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedCplusDemangle);
		// Recreated provider, need to get new handle on action
		calleeNameTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeNameTransferAction);

		line = 9;
		col = 4;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_0041d150'
		// Ensure the callee name transfer action is not active
		assertEquals("DAT_0041d150", currentToken.getText());
		assertNotEnabled(calleeNameTransferAction, getProviderContext());

		line = 10;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_10'
		// Ensure the callee name transfer action is not active
		assertEquals("local_10", currentToken.getText());
		assertNotEnabled(calleeNameTransferAction, getProviderContext());

		line = 24;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated callee token 'FUN_0040c987'
		// Ensure the callee name transfer action is active and working
		assertEquals("FUN_0040c987", currentToken.getText());
		assertEnabled(calleeNameTransferAction, getProviderContext());
		performAction(calleeNameTransferAction);
		waitForDecompile(correlatedPanel);

		// Check updated function name
		currentToken = getCurrentToken(correlatedPanel, Side.RIGHT);
		assertEquals("internal_cplus_demangle", currentToken.getText());
	}

	@Test
	public void testCalleeFullTypeTransferAction() throws RuntimeException {
		final String actionName =
			ApplyCalleeSignatureWithDatatypesFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedMain);
		DockingActionIf calleeFullSignatureTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeFullSignatureTransferAction);

		line = 12;
		col = 9;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated callee token 'xstrdup'
		// Ensure the callee name transfer action is not active
		assertEquals("xstrdup", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedCplusDemangle);
		// Recreated provider, need to get new handle on action
		calleeFullSignatureTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeFullSignatureTransferAction);

		line = 9;
		col = 4;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_0041d150'
		// Ensure the callee name transfer action is not active
		assertEquals("DAT_0041d150", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		line = 10;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_10'
		// Ensure the callee name transfer action is not active
		assertEquals("local_10", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		line = 24;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated callee token 'FUN_0040c987'
		// Ensure the callee name transfer action is active and working
		assertEquals("FUN_0040c987", currentToken.getText());
		assertEnabled(calleeFullSignatureTransferAction, getProviderContext());
		performAction(calleeFullSignatureTransferAction);
		waitForDecompile(correlatedPanel);

		// Check updated function name
		line = 25;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		assertEquals("internal_cplus_demangle", currentToken.getText());

		// Check updated function signature
		FunctionSignature debugSig = getFunctionFromOffset(progDemangler24Debug,
			DEMANGLER_24_DEBUG_INTERNAL_CPLUS_DEMANGLE_OFFSET).getSignature();
		FunctionSignature strippedSig = getFunctionFromOffset(progDemangler24Stripped,
			DEMANGLER_24_STRIPPED_INTERNAL_CPLUS_DEMANGLE_OFFSET).getSignature();

		assertEquals(debugSig.getReturnType().getDisplayName(),
			strippedSig.getReturnType().getDisplayName());
		assertEquals(debugSig.getArguments().length, strippedSig.getArguments().length);

		for (int i = 0; i < debugSig.getArguments().length; i++) {
			ParameterDefinition p = debugSig.getArguments()[i];
			ParameterDefinition p2 = strippedSig.getArguments()[i];
			assertEquals(p.getDataType().getDisplayName(), p2.getDataType().getDisplayName());
		}

		// Check full datatype for work_stuff
		ProgramBasedDataTypeManager debugDtm = progDemangler24Debug.getDataTypeManager();
		Structure debugStructure =
			(Structure) debugDtm.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));
		assertNotNull(debugStructure);

		ProgramBasedDataTypeManager strippedDtm = progDemangler24Stripped.getDataTypeManager();
		Structure strippedStructure = (Structure) strippedDtm
				.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));
		assertNotNull(strippedStructure);

		assertEquals(debugStructure.getNumComponents(), strippedStructure.getNumComponents());
	}

	@Test
	public void testCalleeSkeletonTypeTransferAction() throws RuntimeException {
		final String actionName = ApplyCalleeEmptySignatureFromMatchedTokensAction.ACTION_NAME;
		int line;
		int col;
		ClangToken currentToken;

		DecompilerCodeComparisonPanel uncorrelatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedMain);
		DockingActionIf calleeFullSignatureTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeFullSignatureTransferAction);

		line = 12;
		col = 9;
		currentToken = setDecompLocation(uncorrelatedPanel, Side.LEFT, line, col);
		// Cursor is now on uncorrelated callee token 'xstrdup'
		// Ensure the callee name transfer action is not active
		assertEquals("xstrdup", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		DecompilerCodeComparisonPanel correlatedPanel =
			preparePanel(funcDemangler24DebugCplusDemangle, funcDemangler24StrippedCplusDemangle);
		// Recreated provider, need to get new handle on action
		calleeFullSignatureTransferAction = getLocalAction(provider, actionName);
		assertNotNull(calleeFullSignatureTransferAction);

		line = 9;
		col = 4;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated global variable token 'DAT_0041d150'
		// Ensure the callee name transfer action is not active
		assertEquals("DAT_0041d150", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		line = 10;
		col = 0;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated local variable token 'local_10'
		// Ensure the callee name transfer action is not active
		assertEquals("local_10", currentToken.getText());
		assertNotEnabled(calleeFullSignatureTransferAction, getProviderContext());

		line = 24;
		col = 11;
		currentToken = setDecompLocation(correlatedPanel, Side.RIGHT, line, col);
		// Cursor is now on correlated callee token 'FUN_0040c987'
		// Ensure the callee name transfer action is active and working
		assertEquals("FUN_0040c987", currentToken.getText());
		assertEnabled(calleeFullSignatureTransferAction, getProviderContext());
		performAction(calleeFullSignatureTransferAction);
		waitForDecompile(correlatedPanel);

		// Check updated function name
		currentToken = getCurrentToken(correlatedPanel, Side.RIGHT);
		assertEquals("internal_cplus_demangle", currentToken.getText());

		// Check updated function signature 
		FunctionSignature debugSig = getFunctionFromOffset(progDemangler24Debug,
			DEMANGLER_24_DEBUG_INTERNAL_CPLUS_DEMANGLE_OFFSET).getSignature();
		FunctionSignature strippedSig = getFunctionFromOffset(progDemangler24Stripped,
			DEMANGLER_24_STRIPPED_INTERNAL_CPLUS_DEMANGLE_OFFSET).getSignature();

		assertEquals(debugSig.getReturnType().getDisplayName(),
			strippedSig.getReturnType().getDisplayName());
		assertEquals(debugSig.getArguments().length, strippedSig.getArguments().length);

		for (int i = 0; i < debugSig.getArguments().length; i++) {
			ParameterDefinition p = debugSig.getArguments()[i];
			ParameterDefinition p2 = strippedSig.getArguments()[i];
			assertEquals(p.getDataType().getDisplayName(), p2.getDataType().getDisplayName());
		}

		// Check that an empty struct is in the data type manager
		ProgramBasedDataTypeManager dtm = progDemangler24Stripped.getDataTypeManager();
		Structure structure =
			(Structure) dtm.getDataType(new DataTypePath("/DWARF/cplus-dem.c", "work_stuff"));

		assertNotNull(structure);
		assertTrue(structure.isNotYetDefined());
		assertTrue(structure.isZeroLength());
		assertEquals(0, structure.getNumComponents());
	}

	// Setup and focus to a decompiler comparison between the two selected functions. Wait for
	// the decompilation to complete so that subsequent calls to navigation, etc. work correctly
	private DecompilerCodeComparisonPanel preparePanel(Function leftFunc, Function rightFunc) {
		if (provider != null) {
			// Always want to clear out existing comparison
			closeProvider(provider);
		}

		provider = compareFunctions(Set.of(leftFunc, rightFunc));

		DecompilerCodeComparisonPanel decompPanel = findDecompilerPanel(provider);
		waitForDecompile(decompPanel);
		decompPanel.setSynchronizedScrolling(true);
		setActivePanel(provider, decompPanel);

		assertEquals(decompPanel.getFunction(Side.LEFT), leftFunc);
		assertEquals(decompPanel.getFunction(Side.RIGHT), rightFunc);

		return decompPanel;
	}

	private Function getFunctionFromOffset(Program prog, long offset) {
		return prog.getFunctionManager()
				.getFunctionAt(
					prog.getAddressFactory().getDefaultAddressSpace().getAddress(offset));
	}

	private void assertEnabled(DockingActionIf action, ActionContext context) {
		assertTrue(runSwing(() -> action.isEnabledForContext(context)));
	}

	private void assertNotEnabled(DockingActionIf action, ActionContext context) {
		assertFalse(runSwing(() -> action.isEnabledForContext(context)));
	}

	// Test programs are always opened read-only, so set context override
	private ActionContext getProviderContext() {
		ActionContext context = provider.getActionContext(null);
		if (context instanceof DualDecompilerActionContext dualDecompContext) {
			dualDecompContext.setOverrideReadOnly(true);
		}

		return context;
	}

}
