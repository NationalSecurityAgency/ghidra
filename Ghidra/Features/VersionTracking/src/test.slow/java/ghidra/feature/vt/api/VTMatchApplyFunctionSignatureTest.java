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
package ghidra.feature.vt.api;

import static ghidra.feature.vt.db.VTTestUtils.addr;
import static ghidra.feature.vt.db.VTTestUtils.createMatchSetWithOneMatch;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.*;

import org.junit.*;

import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.markuptype.FunctionSignatureMarkupType;
import ghidra.feature.vt.gui.plugin.*;
import ghidra.feature.vt.gui.task.*;
import ghidra.feature.vt.gui.util.MatchInfo;
import ghidra.feature.vt.gui.util.VTMatchApplyChoices.*;
import ghidra.feature.vt.gui.util.VTOptionDefines;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.store.LockException;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class VTMatchApplyFunctionSignatureTest extends AbstractGhidraHeadedIntegrationTest {

//	private static final String TEST_SOURCE_PROGRAM_NAME = "VersionTracking/WallaceSrc";
//	private static final String TEST_DESTINATION_PROGRAM_NAME = "VersionTracking/WallaceVersion2";
	private TestEnv env;
	private PluginTool tool;
	private VTController controller;
	private VTSessionDB session;
	private Program sourceProgram;
	private Program destinationProgram;
	private Address sourceAddress;
	private Address destinationAddress;
	private VTMatch testMatch;
	private Function sourceFunction;
	private Function destinationFunction;

	//  addPerson 004011a0   FUN... 004011a0    2 params
	//  call_Strncpy 00401300   FUN... 00401310    3 params w/ matching types
	//  Canary_Tester_... 0040131c   FUN... 0040132c    1 param & identical signature

	public VTMatchApplyFunctionSignatureTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		env = new TestEnv();
		sourceProgram = createSourceProgram();// env.getProgram(TEST_SOURCE_PROGRAM_NAME);
		destinationProgram = createDestinationProgram();// env.getProgram(TEST_DESTINATION_PROGRAM_NAME);
		tool = env.getTool();

		tool.addPlugin(VTPlugin.class.getName());
		VTPlugin plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);

		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);

		runSwing(new Runnable() {
			@Override
			public void run() {
				controller.openVersionTrackingSession(session);
			}
		});

		setAllOptionsToDoNothing();

//
//		env = new VTTestEnv();
//		session = env.createSession(TEST_SOURCE_PROGRAM_NAME, TEST_DESTINATION_PROGRAM_NAME);
//		try {
//			correlator =
//				vtTestEnv.correlate(new ExactMatchInstructionsProgramCorrelatorFactory(), null,
//					TaskMonitorAdapter.DUMMY_MONITOR);
//		}
//		catch (Exception e) {
//			Assert.fail(e.getMessage());
//			e.printStackTrace();
//		}
//		sourceProgram = env.getSourceProgram();
//		destinationProgram = env.getDestinationProgram();
//		controller = env.getVTController();
//		env.showTool();
//
//		Logger functionLogger = Logger.getLogger(FunctionDB.class);
//		functionLogger.setLevel(Level.TRACE);
//
//		Logger variableLogger = Logger.getLogger(VariableSymbolDB.class);
//		variableLogger.setLevel(Level.TRACE);

	}

	private StructureDataType getPersonStruct(Program program) {
		StructureDataType struct =
			new StructureDataType(CategoryPath.ROOT, "Person", 0, program.getDataTypeManager());
		TypeDef personType =
			new TypedefDataType(CategoryPath.ROOT, "_person", struct, program.getDataTypeManager());
		struct.add(IntegerDataType.dataType, "id", null);
		ArrayDataType nameArray = new ArrayDataType(CharDataType.dataType, 32, 1);
		struct.add(nameArray, "name", null);
		struct.add(BooleanDataType.dataType, "likesCheese", null);
		struct.add(PointerDataType.getPointer(personType, program.getDataTypeManager()), "next",
			null);
		return struct;
	}

	private Program createSourceProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Wallace", ProgramBuilder._X86, this);
		Program p = builder.getProgram();

		builder.createClassNamespace("Gadget", null, SourceType.IMPORTED);

		StructureDataType struct = getPersonStruct(p);
		Pointer ptr1 = PointerDataType.getPointer(struct, p.getDataTypeManager());
		Pointer ptr2 = PointerDataType.getPointer(ptr1, p.getDataTypeManager());

		Pointer charPtr = PointerDataType.getPointer(CharDataType.dataType, p.getDataTypeManager());

		builder.createMemory(".text", "0x401000", 0x200);

		// undefined _stdcall addPerson(Person * * list, char * personName)
		builder.createEmptyFunction("addPerson", null, CompilerSpec.CALLING_CONVENTION_stdcall,
			false, "0x4011a0", 10, DataType.DEFAULT, new ParameterImpl("list", ptr2, p),
			new ParameterImpl("personName", charPtr, p));

		// undefined _thiscall Gadget::use(Gadget * this, Person * person)
		builder.createEmptyFunction("use", "Gadget", CompilerSpec.CALLING_CONVENTION_thiscall,
			false, "0x401040", 10, DataType.DEFAULT, new ParameterImpl("person", ptr1, p));

		return p;
	}

	private Program createDestinationProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("WallaceVersion2", ProgramBuilder._X86, this);
		Program p = builder.getProgram();

		Pointer ptr1 = PointerDataType.getPointer(VoidDataType.dataType, p.getDataTypeManager());
		Pointer ptr2 = PointerDataType.getPointer(ptr1, p.getDataTypeManager());

		Pointer charPtr = PointerDataType.getPointer(CharDataType.dataType, p.getDataTypeManager());

		builder.createMemory(".text", "0x401000", 0x200);

		// undefined _stdcall FUN_004011a0(void * * param_1, char * param_2)
		Function f1 = builder.createEmptyFunction((String) null, (String) null,
			CompilerSpec.CALLING_CONVENTION_stdcall, "0x4011a0", 10, DataType.DEFAULT, ptr2,
			charPtr);

		// undefined _thiscall FUN_00401040(void * this, undefined4 param_1)
		Function f2 = builder.createEmptyFunction((String) null, (String) null,
			CompilerSpec.CALLING_CONVENTION_thiscall, "0x401040", 10, DataType.DEFAULT,
			Undefined4DataType.dataType);

		int txId = p.startTransaction("Set SourceType");
		try {
			f1.setSignatureSource(SourceType.DEFAULT);
			f2.setSignatureSource(SourceType.ANALYSIS);
		}
		finally {
			p.endTransaction(txId, true);
		}

		return p;
	}

	private Program createToyDestinationProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("helloProgram", ProgramBuilder._TOY, this);
		Program p = builder.getProgram();

		builder.createMemory(".text", "0x10938", 0x10);

		builder.createEmptyFunction(null, "0x10938", 0x10, DataType.DEFAULT);

		return p;
	}

	private void setAllOptionsToDoNothing() {
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.PLATE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PRE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.END_OF_LINE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.REPEATABLE_COMMENT, CommentChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.POST_COMMENT, CommentChoices.EXCLUDE);
		//	applyOptions.putEnum(VTOptionDefines.DATA_REFERENCE, LabelChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME, FunctionNameChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_SIGNATURE, FunctionSignatureChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.HIGHEST_NAME_PRIORITY,
			HighestSourcePriorityChoices.USER_PRIORITY_HIGHEST);
		applyOptions.setEnum(VTOptionDefines.PARAMETER_COMMENTS, CommentChoices.EXCLUDE);
//		applyOptions.putEnum(VTOptionDefines.DATA_MATCH_DATA_TYPE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(VTOptionDefines.LABELS, LabelChoices.EXCLUDE);
	}

	@After
	public void tearDown() throws Exception {
		if (sourceProgram != null) {
			sourceProgram.release(this);
		}
		if (destinationProgram != null) {
			destinationProgram.release(this);
		}
//		env.release(sourceProgram);
//		env.release(destinationProgram);
		env.dispose();

	}

	@Test
	public void testApplyMatch_ReplaceSignature_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		setReturnType(sourceFunction, new PointerDataType(new IntegerDataType(), 4),
			SourceType.USER_DEFINED);

		checkSignatures("int * addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		VtTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("int * addPerson(Person * * list, char * personName)",
			"int * FUN_004011a0(Person * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		task = new ClearMatchTask(controller, matches);
		runTask(session, task);

		// Verify unapply.
		checkSignatures("int * addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis() throws Exception {
		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignature_CustomSameNumParams_ThisToThis() throws Exception {
		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		int txId = sourceProgram.startTransaction("Modify Source");
		try {
			sourceFunction.setCustomVariableStorage(true);

			sourceFunction.getParameter(0).setDataType(sourceFunction.getParameter(1).getDataType(),
				SourceType.USER_DEFINED);
		}
		finally {
			sourceProgram.endTransaction(txId, true);
		}

		DataType personType = sourceProgram.getDataTypeManager().getDataType("/Person");
		assertNotNull(personType);

		txId = destinationProgram.startTransaction("Modify Destination");
		try {
			destinationFunction.setReturnType(personType, SourceType.USER_DEFINED);
		}
		finally {
			destinationProgram.endTransaction(txId, true);
		}

		// Check modified values
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(void * this, Person * __return_storage_ptr__, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply. (return type not replaced with undefined due to lower priority)
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(Person * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(void * this, Person * __return_storage_ptr__, undefined4 param_1)");

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConvention2() throws Exception {
		useMatch("0x00401040", "0x00401040");

		setCallingConvention(sourceFunction, "__cdecl");
//		removeParameter(sourceFunction, 0);
		setCallingConvention(destinationFunction, "__stdcall");
//		removeParameter(destinationFunction, 0);

		// Check initial values
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkInline(false, false);
		checkCallingConvention("__cdecl", "__stdcall");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkCallingConvention("__cdecl", "__cdecl");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkCallingConvention("__cdecl", "__stdcall");
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageUseSameLanguage()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		setLanguage(sourceFunction, "Toy:LE:32:default", "default");
		setCallingConvention(sourceFunction, "__stdcall");
//		removeParameter(sourceFunction, 0);
		setCallingConvention(destinationFunction, "__cdecl");
//		removeParameter(destinationFunction, 0);

		// Check initial values
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkInline(false, false);
		checkCallingConvention("__stdcall", "__cdecl");
		checkCompilerSpecID("default", "windows");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkCallingConvention("__stdcall", "__cdecl");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkCallingConvention("__stdcall", "__cdecl");
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageUseNameMatch()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		setLanguage(sourceFunction, "Toy:LE:32:default", "default");
		setCallingConvention(sourceFunction, "__stdcall");
//		removeParameter(sourceFunction, 0);
		setCallingConvention(destinationFunction, "__cdecl");
//		removeParameter(destinationFunction, 0);

		// Check initial values
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkInline(false, false);
		checkCallingConvention("__stdcall", "__cdecl");
		assertNotNull(sourceFunction);
		assertNotNull(destinationFunction);
		checkCompilerSpecID("default", "windows");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkCallingConvention("__stdcall", "__stdcall");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkCallingConvention("__stdcall", "__cdecl");
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageFailUsingNameMatch()
			throws Exception {

		runSwing(new Runnable() {
			@Override
			public void run() {
				controller.closeCurrentSessionIgnoringChanges();
			}
		});

		env.release(destinationProgram);
		destinationProgram = createToyDestinationProgram();// env.getProgram("helloProgram"); // get a program without cdecl
		session =
			VTSessionDB.createVTSession(testName.getMethodName() + " - Test Match Set Manager",
				sourceProgram, destinationProgram, this);
		runSwing(new Runnable() {
			@Override
			public void run() {
				controller.openVersionTrackingSession(session);
			}
		});

		useMatch("0x00401040", "0x00010938");

		setCallingConvention(sourceFunction, "__cdecl");
//		removeParameter(sourceFunction, 0);
		setCallingConvention(destinationFunction, "__stdcall");

		// Check initial values
		checkSignatures("undefined use(Person * person)", "undefined FUN_00010938(void)");
		checkInline(false, false);
		checkCallingConvention("__cdecl", "__stdcall");
		assertNotNull(sourceFunction);
		assertNotNull(destinationFunction);
		checkCompilerSpecID("windows", "default");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkCallingConvention("__cdecl", "__stdcall");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00010938(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined use(Person * person)", "undefined FUN_00010938(void)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkCallingConvention("__cdecl", "__stdcall");
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	@Test
	public void testApplyMatch_ReplaceMultiple1_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		setInline(sourceFunction, true);
		setNoReturn(sourceFunction, true);
		setReturnType(sourceFunction, new FloatDataType(), SourceType.ANALYSIS);

		// Check initial values
		checkSignatures("float addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(true, false);
		checkNoReturn(true, false);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("float addPerson(Person * * list, char * personName)",
			"float FUN_004011a0(Person * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(true, true);
		checkNoReturn(true, true);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("float addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(true, false);
		checkNoReturn(true, false);
	}

	@Test
	public void testApplyMatch_ReplaceMultiple2_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterComment(sourceFunction, 1, "Name of the person");

		setReturnType(destinationFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterName(destinationFunction, 1, "name", SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "Last Name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Check initial values
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE_DEFAULTS_ONLY);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(Person * * list, char * name)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name\nName of the person");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");
	}

	@Test
	public void testApplyMatch_ReplaceMultiple3_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterComment(sourceFunction, 1, "Name of the person");

		setReturnType(destinationFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterName(destinationFunction, 1, "name", SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "Last Name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Check initial values
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(Person * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, null);
		checkParameterComments(destinationFunction, 1, "Name of the person");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");
	}

	@Test
	public void testApplyMatch_ReplaceMultiple4_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterComment(sourceFunction, 1, "Name of the person");

		setReturnType(destinationFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterName(destinationFunction, 1, "name", SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "Last Name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Check initial values
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.EXCLUDE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");
	}

	@Test
	public void testApplyMatch_ReplaceMultiple5_SameNumParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		setParameterName(sourceFunction, 0, null, SourceType.DEFAULT);
		setParameterComment(sourceFunction, 1, "Name of the person");

		setReturnType(destinationFunction, new FloatDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterName(destinationFunction, 1, "name", SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "Last Name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Check initial values
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.EXCLUDE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.EXCLUDE);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.REPLACE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, "Name of the person");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "Last Name");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_FewerDestinationParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(destinationFunction, 1);

		setParameterComment(sourceFunction, 0, "a list");
		setParameterComment(sourceFunction, 1, "The person's name");

		setReturnType(destinationFunction, new WordDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, false);

		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(void * * list)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "The entire list");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(Person * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "The entire list\na list");
		checkParameterComments(destinationFunction, 1, "The person's name");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(void * * list)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "The entire list");
	}

	@Test
	public void testApplyMatch_ReplaceSignature2_FewerDestinationParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(destinationFunction, 1);

		setParameterComment(sourceFunction, 0, "a list");
		setParameterComment(sourceFunction, 1, "The person's name");

		setReturnType(destinationFunction, new WordDataType(), SourceType.USER_DEFINED);
		setParameterName(destinationFunction, 0, "list", SourceType.IMPORTED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, false);

		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(void * * list)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.OVERWRITE_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "The entire list");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(void * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "a list");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"word FUN_004011a0(void * * list)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(sourceFunction, 1, "The person's name");
		checkParameterComments(destinationFunction, 0, "The entire list");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_FewerSourceParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(sourceFunction, 1);

		setParameterComment(sourceFunction, 0, "a list");

		setReturnType(destinationFunction, new WordDataType(), SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "The person's name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.EXCLUDE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "The person's name");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list)", "word FUN_004011a0(void * * list)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list\na list");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "The person's name");
	}

	@Test
	public void testApplyMatch_ReplaceSignature2_FewerSourceParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(sourceFunction, 1);

		setParameterComment(sourceFunction, 0, "a list");

		setReturnType(destinationFunction, new WordDataType(), SourceType.USER_DEFINED);
		setParameterComment(destinationFunction, 0, "The entire list");
		setParameterComment(destinationFunction, 1, "The person's name");
		setInline(destinationFunction, true);
		setNoReturn(destinationFunction, true);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.NAME_MATCH);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "The person's name");

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(Person * * list)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list\na list");

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(void * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list");
		checkParameterComments(destinationFunction, 1, "The person's name");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_SomeParamsAndNoParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		setReturnType(sourceFunction, new PointerDataType(new IntegerDataType(), 4),
			SourceType.ANALYSIS);
		setVarArgs(sourceFunction, true);
		removeParameter(destinationFunction, 1);
		removeParameter(destinationFunction, 0);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		checkSignatures("int * addPerson(Person * * list, char * personName, ...)",
			"undefined FUN_004011a0()");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, null);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("int * addPerson(Person * * list, char * personName, ...)",
			"int * FUN_004011a0(Person * * list, char * personName, ...)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, null);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("int * addPerson(Person * * list, char * personName, ...)",
			"undefined FUN_004011a0()");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, null);
	}

	@Test
	public void testApplyMatch_ReplaceSignature_NoParamsAndSomeParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(sourceFunction, 1);
		removeParameter(sourceFunction, 0);
		setVarArgs(destinationFunction, true);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		checkSignatures("undefined addPerson(void)",
			"undefined FUN_004011a0(void * * param_1, char * param_2, ...)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(destinationFunction, 0, null);
		checkParameterComments(destinationFunction, 1, null);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(void)",
			"undefined FUN_004011a0(void * * param_1, char * param_2, ...)");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(destinationFunction, 0, null);
		checkParameterComments(destinationFunction, 1, null);
	}

	@Test
	public void testApplyMatch_ReplaceSignature_NoParamsAndNoParams() throws Exception {
		useMatch("0x004011a0", "0x004011a0");

		// Check initial values
		checkSignatures("undefined addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");

		// force known values for the test
		removeParameter(sourceFunction, 1);
		removeParameter(sourceFunction, 0);
		removeParameter(destinationFunction, 1);
		removeParameter(destinationFunction, 0);

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(INLINE, ReplaceChoices.REPLACE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);

		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0()");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);// Signature Source differs.
		checkInline(false, false);
		checkNoReturn(false, false);
		checkSignatureSource(SourceType.USER_DEFINED, SourceType.DEFAULT);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		// Test Apply
		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);

		// Verify apply.
		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkSignatureSource(SourceType.USER_DEFINED, SourceType.USER_DEFINED);

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, matches);
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0()");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkSignatureSource(SourceType.USER_DEFINED, SourceType.DEFAULT);
	}

	//==================================================================================================
	// Helper Methods
	//==================================================================================================

	@SuppressWarnings("unused")
	private String dumpStatus(List<VTMarkupItem> individualItems) {
		StringBuilder buffer = new StringBuilder();
		int index = 0;
		for (VTMarkupItem vtMarkupItem : individualItems) {
			buffer.append(
				"\nmarkupItem(" + (index++) + ") status = " + vtMarkupItem.getStatus().toString() +
					"  " + vtMarkupItem.getMarkupType().getDisplayName() + ".");
		}
		return buffer.toString();
	}

	private void useMatch(String sourceAddressString, String destinationAddressString)
			throws Exception {
		sourceAddress = addr(sourceAddressString, sourceProgram);
		destinationAddress = addr(destinationAddressString, destinationProgram);

		testMatch = createMatchSetWithOneMatch(session, sourceAddress, destinationAddress);

		assertNotNull(testMatch);

		sourceFunction = sourceProgram.getFunctionManager().getFunctionAt(sourceAddress);
		assertNotNull(sourceFunction);
		destinationFunction =
			destinationProgram.getFunctionManager().getFunctionAt(destinationAddress);
		assertNotNull(destinationFunction);
	}

	private void checkSignatures(String expectedSourceSignature,
			String expectedDestinationSignature) {

		final String[] sourceStringBox = new String[1];
		final String[] destinationStringBox = new String[1];

		runSwing(new Runnable() {
			@Override
			public void run() {
				sourceStringBox[0] = sourceFunction.getPrototypeString(false, false);
				destinationStringBox[0] = destinationFunction.getPrototypeString(false, false);
			}
		});

		assertEquals(expectedSourceSignature, sourceStringBox[0]);
		assertEquals(expectedDestinationSignature, destinationStringBox[0]);
	}

	private void checkSignatureSource(SourceType expectedSourceSigSourceType,
			SourceType expectedDestinationSigSourceType) {

		assertEquals(expectedSourceSigSourceType, sourceFunction.getSignatureSource());
		assertEquals(expectedDestinationSigSourceType, destinationFunction.getSignatureSource());
	}

	private void checkInline(boolean expectedSourceInline, boolean expectedDestinationInline) {

		assertEquals(expectedSourceInline, sourceFunction.isInline());
		assertEquals(expectedDestinationInline, destinationFunction.isInline());
	}

	private void checkNoReturn(boolean expectedSourceNoReturn,
			boolean expectedDestinationNoReturn) {

		assertEquals(expectedSourceNoReturn, sourceFunction.hasNoReturn());
		assertEquals(expectedDestinationNoReturn, destinationFunction.hasNoReturn());
	}

	private void checkCallingConvention(String expectedSourceCallingConventionName,
			String expectedDestinationCallingConventionName) {

		assertEquals(expectedSourceCallingConventionName,
			sourceFunction.getCallingConventionName());
		assertEquals(expectedDestinationCallingConventionName,
			destinationFunction.getCallingConventionName());
	}

	private void checkCompilerSpecID(String expectedSourceCompilerSpecID,
			String expectedDestinationCompilerSpecID) {

		CompilerSpec sourceCompilerSpec = sourceFunction.getProgram().getCompilerSpec();
		String sourceCompilerSpecID = sourceCompilerSpec.getCompilerSpecID().toString();
		assertEquals(expectedSourceCompilerSpecID, sourceCompilerSpecID);
//		String sourceCompilerSpecDescription =
//				sourceCompilerSpec.getCompilerSpecDescription().toString();
//		assertEquals(expectedSourceCompilerSpec, sourceCompilerSpecDescription);

//		CompilerSpec destinationCompilerSpec = destinationFunction.getProgram().getCompilerSpec();
//		String destinationCompilerSpecID = destinationCompilerSpec.getCompilerSpecID().toString();
		assertEquals(expectedSourceCompilerSpecID, sourceCompilerSpecID);
//		String destinationCompilerSpecDescription =
//				destinationCompilerSpec.getCompilerSpecDescription().toString();
//		assertEquals(expectedDestinationCompilerSpec, destinationCompilerSpecDescription);
	}

	private void checkFunctionSignatureStatus(VTMatch match, VTMarkupItemStatus expectedStatus) {
		VTMarkupItem markupItem = getFunctionSignatureMarkup(match);
		if (expectedStatus == null && markupItem == null) {
			return;
		}
		assertNotNull(markupItem);
		checkMarkupStatus(markupItem, expectedStatus);
	}

	private void checkParameterComments(Function function, int ordinal, String expectedComment) {
		Parameter parameter = function.getParameter(ordinal);
		String actualComment = parameter.getComment();
		assertEquals(expectedComment, actualComment);
	}

	private void checkMarkupStatus(VTMarkupItem vtMarkupItem, VTMarkupItemStatus expectedStatus) {
		assertEquals(
			vtMarkupItem.getMarkupType().getDisplayName() + " with source of " +
				vtMarkupItem.getSourceAddress().toString() + " has wrong status ",
			expectedStatus, vtMarkupItem.getStatus());
	}

	private VTMarkupItem getFunctionSignatureMarkup(VTMatch match) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitorAdapter.DUMMY_MONITOR);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			if (vtMarkupItem.getMarkupType() instanceof FunctionSignatureMarkupType) {
				return vtMarkupItem;
			}
		}
		return null;
	}

	private void removeParameter(Function function, int ordinal) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Remove Parameter: " + ordinal);
			function.removeParameter(ordinal);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setReturnType(Function function, DataType returnType, SourceType source)
			throws InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		boolean commit = false;
		try {
			transaction =
				program.startTransaction("Test - Set Return Type: " + returnType.getName());
			function.setReturnType(returnType, source);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	private void setParameterName(Function function, int ordinal, String name, SourceType source)
			throws DuplicateNameException, InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Parameter Name: " + ordinal);
			Parameter parameter = function.getParameter(ordinal);
			parameter.setName(name, source);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setParameterComment(Function function, int ordinal, String comment) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Set Parameter Comment: " + ordinal);
			Parameter parameter = function.getParameter(ordinal);
			parameter.setComment(comment);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setVarArgs(Function function, boolean hasVarArgs) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting VarArgs: " + hasVarArgs);
			function.setVarArgs(hasVarArgs);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setInline(Function function, boolean isInline) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting Inline Flag: " + isInline);
			function.setInline(isInline);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setLanguage(Function function, String languageID, String compilerSpecName)
			throws IllegalStateException, LockException, IncompatibleLanguageException,
			LanguageNotFoundException {
		Program program = function.getProgram();
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

	private void setCallingConvention(Function function, String callingConventionName)
			throws InvalidInputException {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction(
				"Test - Setting Calling Convention: " + callingConventionName);
			function.setCallingConvention(callingConventionName);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void setNoReturn(Function function, boolean hasNoReturn) {
		Program program = function.getProgram();
		int transaction = -1;
		try {
			transaction = program.startTransaction("Test - Setting No Return Flag: " + hasNoReturn);
			function.setNoReturn(hasNoReturn);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private void runTask(VTSession session, VtTask task) {
		int id = session.startTransaction("test");
		try {
			task.run(TaskMonitor.DUMMY);
		}
		finally {
			session.endTransaction(id, true);
		}
	}
}
