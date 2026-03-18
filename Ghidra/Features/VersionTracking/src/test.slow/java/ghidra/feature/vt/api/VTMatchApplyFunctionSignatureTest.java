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

import static ghidra.feature.vt.db.VTTestUtils.*;
import static ghidra.feature.vt.gui.util.VTOptionDefines.*;
import static org.junit.Assert.*;

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
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class VTMatchApplyFunctionSignatureTest extends AbstractGhidraHeadedIntegrationTest {

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
		sourceProgram = createSourceProgram();
		destinationProgram = createDestinationProgram();
		tool = env.getTool();

		tool.addPlugin(VTPlugin.class.getName());
		VTPlugin plugin = getPlugin(tool, VTPlugin.class);
		controller = new VTControllerImpl(plugin);

		session = new VTSessionDB(testName.getMethodName() + " - Test Match Set Manager",
			sourceProgram, destinationProgram, this);

		runSwing(() -> controller.openVersionTrackingSession(session));

		setAllOptionsToDoNothing();

//		Logger functionLogger = Logger.getLogger(FunctionDB.class);
//		Configurator.setLevel(functionLogger.getName(), org.apache.logging.log4j.Level.TRACE);
//		
//		Logger variableLogger = Logger.getLogger(VariableSymbolDB.class);
//		Configurator.setLevel(variableLogger.getName(), org.apache.logging.log4j.Level.TRACE);

	}

	@After
	public void tearDown() throws Exception {
		if (sourceProgram != null) {
			sourceProgram.release(this);
		}
		if (destinationProgram != null) {
			destinationProgram.release(this);
		}
		if (session != null) {
			session.release(this);
		}
		env.dispose();
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

	//Create Gadget structure - slightly different than usual in last field to simplify test
	private Structure createNonEmptyGadgetStruct() {

		Structure gadgetStruct = new StructureDataType("Gadget", 0);
		PointerDataType charPtr = new PointerDataType(new CharDataType());
		gadgetStruct.add(charPtr, "name", "");
		gadgetStruct.add(new IntegerDataType(), "type", "");
		gadgetStruct.add(new BooleanDataType(), "deployed", "");
		gadgetStruct.add(new DWordDataType(), "workingOn", "");

		return gadgetStruct;

	}

	private Structure createDifferentGadgetStruct() {

		Structure gadgetStruct = new StructureDataType("Gadget", 0);
		PointerDataType charPtr = new PointerDataType(new CharDataType());
		gadgetStruct.add(charPtr, "name", "");
		gadgetStruct.add(new IntegerDataType(), "type", "");
		gadgetStruct.add(new BooleanDataType(), "deployed", "");
		gadgetStruct.add(new PointerDataType(), "workingOn", "");

		return gadgetStruct;

	}

	private Structure createEmptyGadgetStruct() {
		Structure gadgetStruct = new StructureDataType("Gadget", 0);
		return gadgetStruct;
	}

	private Program createSourceProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("Wallace", ProgramBuilder._X86, this);
		try {
			Program p = builder.getProgram();

			builder.createClassNamespace("Gadget", null, SourceType.IMPORTED);

			StructureDataType struct = getPersonStruct(p);
			builder.addDataType(struct);
			Pointer ptr1 = PointerDataType.getPointer(struct, p.getDataTypeManager());
			Pointer ptr2 = PointerDataType.getPointer(ptr1, p.getDataTypeManager());

			Pointer charPtr =
				PointerDataType.getPointer(CharDataType.dataType, p.getDataTypeManager());

			builder.createMemory(".text", "0x401000", 0x200);

			// undefined _stdcall addPerson(Person * * list, char * personName)
			builder.createEmptyFunction("addPerson", null, CompilerSpec.CALLING_CONVENTION_stdcall,
				false, "0x4011a0", 10, DataType.DEFAULT, new ParameterImpl("list", ptr2, p),
				new ParameterImpl("personName", charPtr, p));

			// undefined _thiscall Gadget::use(Gadget * this, Person * person)
			builder.createEmptyFunction("use", "Gadget", CompilerSpec.CALLING_CONVENTION_thiscall,
				false, "0x401040", 10, DataType.DEFAULT, new ParameterImpl("person", ptr1, p));

			builder.createEmptyFunction("createGadget", null,
				CompilerSpec.CALLING_CONVENTION_stdcall, false, "0x401060", 10, DataType.DEFAULT);

			p.addConsumer(this);
			return p;
		}
		finally {
			builder.dispose();
		}
	}

	private Program createDestinationProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("WallaceVersion2", ProgramBuilder._X86, this);
		try {
			Program p = builder.getProgram();

			Pointer ptr1 =
				PointerDataType.getPointer(VoidDataType.dataType, p.getDataTypeManager());
			Pointer ptr2 = PointerDataType.getPointer(ptr1, p.getDataTypeManager());

			Pointer charPtr =
				PointerDataType.getPointer(CharDataType.dataType, p.getDataTypeManager());

			builder.createMemory(".text", "0x401000", 0x200);

			// undefined _stdcall FUN_004011a0(void * * param_1, char * param_2)
			Function f1 = builder.createEmptyFunction((String) null, (String) null,
				CompilerSpec.CALLING_CONVENTION_stdcall, "0x4011a0", 10, DataType.DEFAULT, ptr2,
				charPtr);

			// undefined _thiscall FUN_00401040(void * this, undefined4 param_1)
			Function f2 = builder.createEmptyFunction((String) null, (String) null,
				CompilerSpec.CALLING_CONVENTION_thiscall, "0x401040", 10, DataType.DEFAULT,
				Undefined4DataType.dataType);

			builder.createEmptyFunction((String) null, (String) null,
				CompilerSpec.CALLING_CONVENTION_stdcall, "0x401060", 10, DataType.DEFAULT);

			p.withTransaction("Set SourceType", () -> {
				f1.setSignatureSource(SourceType.DEFAULT);
				f2.setSignatureSource(SourceType.ANALYSIS);
			});

			return p;
		}
		finally {
			builder.dispose();
		}
	}

	private Program createToyDestinationProgram() throws Exception {

		ProgramBuilder builder = new ProgramBuilder("helloProgram", ProgramBuilder._TOY, this);
		try {
			Program p = builder.getProgram();
			builder.createMemory(".text", "0x10938", 0x10);
			builder.createEmptyFunction(null, "0x10938", 0x10, DataType.DEFAULT);
			return p;
		}
		finally {
			builder.dispose();
		}
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("int * addPerson(Person * * list, char * personName)",
			"int * FUN_004011a0(Person * * list, char * personName)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// Verify unapply.
		unapplyTestMatch("int * addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since no option to apply function name there will be no class namespace applied to
		// the destination so no Gadget class data type should exist
		checkClassDataType(false, false);

		// Verify unapply.
		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	// use case: test replace undefined for return and params when they are undefined ptrs
	@Test
	public void testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis_ReplaceUndefinedPointers()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		// update the source function to have a Gadget * type
		tx(sourceProgram, () -> {
			FunctionManager fm = sourceProgram.getFunctionManager();
			Function function = fm.getFunctionAt(addr("0x00401040", sourceProgram));

			ProgramBasedDataTypeManager dtm = sourceProgram.getDataTypeManager();
			DataType existingEmptyGadget = dtm.getDataType(CategoryPath.ROOT, "Gadget");
			assertNotNull(existingEmptyGadget);

			Pointer ptr1 = PointerDataType.getPointer(existingEmptyGadget, dtm);
			function.setReturnType(ptr1, SourceType.USER_DEFINED);
		});

		// update the destination function to have undefined4 * return type and to have param_1 
		// also be a undefined4 *
		tx(destinationProgram, () -> {

			FunctionManager fm = destinationProgram.getFunctionManager();
			Function function = fm.getFunctionAt(addr("0x00401040", destinationProgram));
			ProgramBasedDataTypeManager dtm = destinationProgram.getDataTypeManager();
			Pointer ptr = PointerDataType.getPointer(Undefined4DataType.dataType, dtm);
			function.setReturnType(ptr, SourceType.DEFAULT);

			Parameter[] parameters = function.getParameters();
			parameters[1].setDataType(ptr, parameters[1].getSource());

			function.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED, parameters);
		});

		// Check initial values
		checkSignatures("Gadget * use(Gadget * this, Person * person)",
			"undefined4 * FUN_00401040(void * this, undefined4 * param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_ALWAYS);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE,
			ParameterDataTypeChoices.REPLACE_UNDEFINED_DATA_TYPES_ONLY);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace

		applyTestMatch();

		// Verify apply.
		checkSignatures("Gadget * use(Gadget * this, Person * person)",
			"Gadget * use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// option to apply function name is on, there will be a class namespace applied to
		// the destination so Gadget class data type should exist
		checkClassDataType(true, false);

		// Verify unapply.
		unapplyTestMatch("Gadget * use(Gadget * this, Person * person)",
			"undefined4 * FUN_00401040(void * this, undefined4 * param_1)");

	}

	// Use case: Source has non-empty Gadget, dest has no Gadget; apply empty structs
	@Test
	public void testApplyMatch_ReplaceSignature_EmptyStructureOption_SourceThisParam_DestParamUndefined()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		applySourceNonEmtpyGadget();

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	// replace namespace
		applyOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, true);

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is not an empty structure in the source, but the option to use empty
		// composites is enabled, so dest should be empty.
		checkClassDataType(true, false);

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	// Use case: Source has populated Gadget struct, dest has empty Gadget struct; apply empty structs 
	@Test
	public void testApplyMatch_ReplaceSignature_EmptyStructureOption_SourceThisParam_DestEmptyGadget()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		applySourceNonEmtpyGadget_DestEmtpyGadgetInDtm();

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace	
		applyOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, true);

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is a populated structure in the source replacing an empty
		// one in the dest.  However, the option to use empty structures is on, so the destination
		// Gadget should be empty.
		checkClassDataType(true, false);

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_EmptyStructureOption_SourceReturnGadger_DestReturnUndefined()
			throws Exception {

		useMatch("0x00401060", "0x00401060");

		Structure gadget = makeSrcGadgetNonEmpty();
		PointerDataType ptr = new PointerDataType(gadget);
		setReturnType(sourceFunction, ptr, SourceType.USER_DEFINED);

		// Check initial values
		checkSignatures("Gadget * createGadget(void)",
			"undefined FUN_00401060(void)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace	
		applyOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, true);

		applyTestMatch();

		// Verify apply.
		checkSignatures("Gadget * createGadget(void)",
			"Gadget * createGadget(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		checkGadgetReturnType(false);

		unapplyTestMatch("Gadget * createGadget(void)",
			"undefined FUN_00401060(void)");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_EmptyStructureOptionOff_SourceReturnGadger_DestReturnUndefined()
			throws Exception {

		useMatch("0x00401060", "0x00401060");

		Structure gadget = makeSrcGadgetNonEmpty();
		PointerDataType ptr = new PointerDataType(gadget);
		setReturnType(sourceFunction, ptr, SourceType.USER_DEFINED);

		// Check initial values
		checkSignatures("Gadget * createGadget(void)",
			"undefined FUN_00401060(void)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace	
		applyOptions.setBoolean(VTOptionDefines.USE_EMPTY_COMPOSITES, false);

		applyTestMatch();

		// Verify apply.
		checkSignatures("Gadget * createGadget(void)",
			"Gadget * createGadget(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		checkGadgetReturnType(true);

		unapplyTestMatch("Gadget * createGadget(void)",
			"undefined FUN_00401060(void)");
	}

	// Use case: Source has empty Gadget struct, dest has no Gadget struct
	@Test
	public void testApplyMatch_ReplaceSignature_AndName_SameNumParams_ThisToThis_NoDestGadgetStruct()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();

		// function name choices - note the only difference between this and the 
		// testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis test
		// is that the option to apply the function name was added which then put the
		// destination function in the Gadget namespace which then causes the this param to be 
		// a Gadget *
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is an empty structure in the source so should be empty in dest
		checkClassDataType(true, false);

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	// Use case: Source has populated Gadget struct, dest has empty Gadget struct
	@Test
	public void testApplyMatch_ReplaceSignature_AndName_SameNumParams_ThisToThis_EmptyDestGadgetStruct()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		Structure srcGadget = applySourceNonEmtpyGadget_DestEmtpyGadgetInDtm();

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();

		// function name choices - note the only difference between this and the 
		// testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis test
		// is that the option to apply the function name was added which then put the
		// destination function in the Gadget namespace which then causes the this param to be 
		// a Gadget *
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace	

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is a populated structure in the source replacing an empty
		// one in the dest so the resulting one in dest should be same populated on from source
		ProgramBasedDataTypeManager destDtm = destinationProgram.getDataTypeManager();
		DataType destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isEquivalent(srcGadget));

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	// Use case: Source has populated Gadget struct, dest has same Gadget struct
	// make sure no .conflict created
	@Test
	public void testApplyMatch_ReplaceSignature_AndName_SameNumParams_ThisToThis_SameDestGadgetStruct()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		ProgramBasedDataTypeManager sourceDtm = sourceProgram.getDataTypeManager();
		ProgramBasedDataTypeManager destDtm = destinationProgram.getDataTypeManager();

		DataType existingEmptyGadgetStruct = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertNotNull(existingEmptyGadgetStruct);

		// replace the source empty gadget with a populated one
		Structure gadgetStruct = createNonEmptyGadgetStruct();
		tx(sourceDtm, () -> {
			sourceDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType updatedSourceGadget = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(updatedSourceGadget.isEquivalent(gadgetStruct));

		// add same Gadget to the destination program
		tx(destDtm, () -> {
			destDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isEquivalent(gadgetStruct));

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();

		// function name choices - note the only difference between this and the 
		// testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis test
		// is that the option to apply the function name was added which then put the
		// destination function in the Gadget namespace which then causes the this param to be 
		// a Gadget *
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is a populated structure in the source and the same one in
		// one in the dest so the resulting one in dest should be same populated on from source
		destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isEquivalent(gadgetStruct));

		DataType gadgetConflict = destDtm.getDataType(CategoryPath.ROOT, "Gadget.conflict");
		assertNull(gadgetConflict);

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	// Use case: Source has populated Gadget struct, dest has different non-empty Gadget struct
	// make sure .conflict IS created
	@Test
	public void testApplyMatch_ReplaceSignature_AndName_SameNumParams_ThisToThis_DiffDestGadgetStruct()
			throws Exception {

		useMatch("0x00401040", "0x00401040");

		ProgramBasedDataTypeManager sourceDtm = sourceProgram.getDataTypeManager();
		ProgramBasedDataTypeManager destDtm = destinationProgram.getDataTypeManager();

		DataType existingEmptyGadgetStruct = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertNotNull(existingEmptyGadgetStruct);

		// replace the source empty gadget with a populated one
		Structure gadgetStruct = createNonEmptyGadgetStruct();
		tx(sourceDtm, () -> {
			sourceDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType updatedSourceGadget = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(updatedSourceGadget.isEquivalent(gadgetStruct));

		// add different Gadget to the destination program
		Structure differentGadgetStruct = createDifferentGadgetStruct();
		tx(destDtm, () -> {
			destDtm.addDataType(differentGadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isEquivalent(differentGadgetStruct));

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();

		// function name choices - note the only difference between this and the 
		// testApplyMatch_ReplaceSignature_SameNumParams_ThisToThis test
		// is that the option to apply the function name was added which then put the
		// destination function in the Gadget namespace which then causes the this param to be 
		// a Gadget *
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE,
			FunctionSignatureChoices.WHEN_SAME_PARAMETER_COUNT);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);
		applyOptions.setBoolean(VTOptionDefines.USE_NAMESPACE_FUNCTIONS, true);	//replace namespace

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined use(Gadget * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Gadget class data type should exist
		// In this test Gadget is a populated structure in the source replacing a different non-empty
		// one in the dest so the resulting one in dest should be the source one with the previous
		// source one named .conflict
		destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isEquivalent(differentGadgetStruct));

		DataType gadgetConflict = destDtm.getDataType(CategoryPath.ROOT, "Gadget.conflict");
		assertTrue(gadgetConflict.isEquivalent(gadgetStruct));

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_CustomSourceNormalDest_SameNumParams_ThisToThis()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		setSourceFunctionThisPointerToPersonStructure();

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

		applyTestMatch();

		// Verify apply. (return type not replaced with undefined due to lower priority)
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(Person * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		// since there is custom storage in this case the this param will be copied over even 
		// though the function isn't in the class namespace so the class data type should exist
		checkClassDataType(true, true);

		assertTrue(destinationFunction.hasCustomVariableStorage());

		unapplyTestMatch("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(void * this, Person * __return_storage_ptr__, undefined4 param_1)");
		assertFalse(destinationFunction.hasCustomVariableStorage());
	}

	@Test
	public void testApplyMatch_ReplaceSignature_AndName_CustomSourceNormalDest_SameNumParams_ThisToThis()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		setSourceFunctionThisPointerToPersonStructure();

		// Check modified values
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(void * this, Person * __return_storage_ptr__, undefined4 param_1)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(VTOptionDefines.FUNCTION_NAME,
			FunctionNameChoices.REPLACE_DEFAULT_ONLY);
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		applyTestMatch();

		// Verify apply. (return type not replaced with undefined due to lower priority)
		checkSignatures("undefined use(Person * this, Person * person)",
			"Person * use(Person * this, Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		assertTrue(destinationFunction.hasCustomVariableStorage());

		// since there is option to apply function name there should be a class namespace applied to
		// the destination so the Person class data type should exist
		checkClassDataType(true, true);

		unapplyTestMatch("undefined use(Person * this, Person * person)",
			"Person * FUN_00401040(void * this, Person * __return_storage_ptr__, undefined4 param_1)");
		assertFalse(destinationFunction.hasCustomVariableStorage());
	}

	@Test
	public void testApplyMatch_ReplaceSignature_CustomSourceAndDest() throws Exception {

		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		setSourceFunctionThisPointerToPersonStructureWithCustomStorage();

		checkSignatures("undefined use(Person * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		applyTestMatch();

		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		assertTrue(destinationFunction.hasCustomVariableStorage());

		unapplyTestMatch("undefined use(Person * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_2)");
	}

	@Test
	public void testApplyMatch_ReplaceSignature_NormalSourceCustomDest() throws Exception {

		useMatch("0x00401040", "0x00401040");

		// Check initial values
		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_1)");

		tx(destinationProgram, () -> {
			destinationFunction.setCustomVariableStorage(true);
		});

		checkSignatures("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_2)");

		// Set the function signature options for this test
		ToolOptions applyOptions = controller.getOptions();
		applyOptions.setEnum(FUNCTION_SIGNATURE, FunctionSignatureChoices.REPLACE);
		applyOptions.setEnum(CALLING_CONVENTION, CallingConventionChoices.SAME_LANGUAGE);
		applyOptions.setEnum(PARAMETER_DATA_TYPES, ParameterDataTypeChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_NAMES, SourcePriorityChoices.REPLACE);
		applyOptions.setEnum(PARAMETER_COMMENTS, CommentChoices.APPEND_TO_EXISTING);
		applyOptions.setEnum(NO_RETURN, ReplaceChoices.EXCLUDE);
		applyOptions.setEnum(FUNCTION_RETURN_TYPE, ParameterDataTypeChoices.REPLACE);

		applyTestMatch();

		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		assertFalse(destinationFunction.hasCustomVariableStorage());

		unapplyTestMatch("undefined use(Gadget * this, Person * person)",
			"undefined FUN_00401040(void * this, undefined4 param_2)");
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConvention2() throws Exception {
		useMatch("0x00401040", "0x00401040");

		setCallingConvention(sourceFunction, "__cdecl");
		setCallingConvention(destinationFunction, "__stdcall");

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

		applyTestMatch();

		// Verify apply.
		checkCallingConvention("__cdecl", "__cdecl");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		unapplyTestMatch("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkCallingConvention("__cdecl", "__stdcall");
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageUseSameLanguage()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		setLanguage(sourceFunction, "Toy:LE:32:default", "default");
		setCallingConvention(sourceFunction, "__stdcall");
		setCallingConvention(destinationFunction, "__cdecl");

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

		applyTestMatch();

		// Verify apply.
		checkCallingConvention("__stdcall", "__cdecl");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		unapplyTestMatch("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkCallingConvention("__stdcall", "__cdecl");
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageUseNameMatch()
			throws Exception {
		useMatch("0x00401040", "0x00401040");

		setLanguage(sourceFunction, "Toy:LE:32:default", "default");
		setCallingConvention(sourceFunction, "__stdcall");
		setCallingConvention(destinationFunction, "__cdecl");

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

		applyTestMatch();

		// Verify apply.
		checkCallingConvention("__stdcall", "__stdcall");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00401040(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		unapplyTestMatch("undefined use(Person * person)",
			"undefined FUN_00401040(undefined4 param_1)");
		checkCallingConvention("__stdcall", "__cdecl");
	}

	@Test
	public void testApplyMatch_ReplaceSignatureAndCallingConventionDifferentLanguageFailUsingNameMatch()
			throws Exception {

		runSwing(() -> controller.closeCurrentSessionIgnoringChanges());

		env.release(destinationProgram);
		destinationProgram = createToyDestinationProgram();// env.getProgram("helloProgram"); // get a program without cdecl
		session = new VTSessionDB(testName.getMethodName() + " - Test Match Set Manager",
			sourceProgram, destinationProgram, this);
		runSwing(() -> controller.openVersionTrackingSession(session));

		useMatch("0x00401040", "0x00010938");

		setCallingConvention(sourceFunction, "__cdecl");
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

		applyTestMatch();

		// Verify apply.
		checkCallingConvention("__cdecl", "__stdcall");
		checkSignatures("undefined use(Person * person)",
			"undefined FUN_00010938(Person * person)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkInline(false, false);
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);

		unapplyTestMatch("undefined use(Person * person)", "undefined FUN_00010938(void)");
		checkCallingConvention("__cdecl", "__stdcall");
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("float addPerson(Person * * list, char * personName)",
			"float FUN_004011a0(Person * * param_1, char * param_2)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(true, true);
		checkNoReturn(true, true);

		unapplyTestMatch("float addPerson(Person * * list, char * personName)",
			"undefined FUN_004011a0(void * * param_1, char * param_2)");
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * param_1, char * personName)",
			"float FUN_004011a0(void * * list, char * name)");
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * param_1, char * personName)",
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * param_1, char * personName)",
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * param_1, char * personName)",
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * list, char * personName)",
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

		applyTestMatch();

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

		unapplyTestMatch("undefined addPerson(Person * * list, char * personName)",
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list)", "word FUN_004011a0(void * * list)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, true);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list\na list");

		unapplyTestMatch("undefined addPerson(Person * * list)",
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined addPerson(Person * * list)",
			"word FUN_004011a0(Person * * list)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, true);
		checkParameterComments(sourceFunction, 0, "a list");
		checkParameterComments(destinationFunction, 0, "The entire list\na list");

		unapplyTestMatch("undefined addPerson(Person * * list)",
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("int * addPerson(Person * * list, char * personName, ...)",
			"int * FUN_004011a0(Person * * list, char * personName, ...)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkParameterComments(sourceFunction, 0, null);
		checkParameterComments(sourceFunction, 1, null);

		unapplyTestMatch("int * addPerson(Person * * list, char * personName, ...)",
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);

		unapplyTestMatch("undefined addPerson(void)",
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

		applyTestMatch();

		// Verify apply.
		checkSignatures("undefined addPerson(void)", "undefined FUN_004011a0(void)");
		assertEquals(VTAssociationStatus.ACCEPTED, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.REPLACED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkSignatureSource(SourceType.USER_DEFINED, SourceType.USER_DEFINED);

		unapplyTestMatch("undefined addPerson(void)", "undefined FUN_004011a0()");
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
		checkInline(false, false);
		checkNoReturn(false, false);
		checkSignatureSource(SourceType.USER_DEFINED, SourceType.DEFAULT);
	}

//==================================================================================================
// Helper Methods
//==================================================================================================

	private Structure makeSrcGadgetNonEmpty() {

		ProgramBasedDataTypeManager sourceDtm = sourceProgram.getDataTypeManager();
		DataType existingEmptyGadgetStruct = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertNotNull(existingEmptyGadgetStruct);

		// replace the source empty gadget with a populated one
		Structure gadgetStruct = createNonEmptyGadgetStruct();
		tx(sourceDtm, () -> {
			sourceDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		return (Structure) sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
	}

	private void applyTestMatch() {
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);

		List<VTMatch> matches = new ArrayList<>();
		matches.add(testMatch);

		ApplyMatchTask task = new ApplyMatchTask(controller, matches);
		runTask(session, task);
	}

	private void unapplyTestMatch(String expectedSrc, String expectedDest) {

		// Test unapply
		ClearMatchTask unapplyTask = new ClearMatchTask(controller, List.of(testMatch));
		runTask(session, unapplyTask);

		// Verify unapply.
		checkSignatures(expectedSrc, expectedDest);
		assertEquals(VTAssociationStatus.AVAILABLE, testMatch.getAssociation().getStatus());
		checkFunctionSignatureStatus(testMatch, VTMarkupItemStatus.UNAPPLIED);
	}

	private Structure applySourceNonEmtpyGadget() {

		ProgramBasedDataTypeManager sourceDtm = sourceProgram.getDataTypeManager();
		DataType existingEmptyGadgetStruct = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertNotNull(existingEmptyGadgetStruct);

		// replace the source empty gadget with a populated one
		Structure gadgetStruct = createNonEmptyGadgetStruct();
		tx(sourceDtm, () -> {
			sourceDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType updatedSourceGadget = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(updatedSourceGadget.isEquivalent(gadgetStruct));

		return gadgetStruct;
	}

	private Structure applySourceNonEmtpyGadget_DestEmtpyGadgetInDtm() {

		ProgramBasedDataTypeManager sourceDtm = sourceProgram.getDataTypeManager();
		ProgramBasedDataTypeManager destDtm = destinationProgram.getDataTypeManager();

		DataType existingEmptyGadgetStruct = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertNotNull(existingEmptyGadgetStruct);

		// replace the source empty gadget with a populated one
		Structure gadgetStruct = createNonEmptyGadgetStruct();

		tx(sourceDtm, () -> {
			sourceDtm.addDataType(gadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType updatedSourceGadget = sourceDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(updatedSourceGadget.isEquivalent(gadgetStruct));

		// add empty gadget to the destination program
		Structure emptyGadgetStruct = createEmptyGadgetStruct();
		tx(destDtm, () -> {
			destDtm.addDataType(emptyGadgetStruct, DataTypeConflictHandler.REPLACE_HANDLER);
		});

		// verify it took
		DataType destGadget = destDtm.getDataType(CategoryPath.ROOT, "Gadget");
		assertTrue(destGadget.isNotYetDefined());

		return gadgetStruct;
	}

	private void setSourceFunctionThisPointerToPersonStructure() {
		tx(sourceProgram, () -> {
			sourceFunction.setCustomVariableStorage(true);

			Parameter param0 = sourceFunction.getParameter(0);
			Parameter param1 = sourceFunction.getParameter(1);
			param0.setDataType(param1.getDataType(), SourceType.USER_DEFINED);
		});

		DataType personType = sourceProgram.getDataTypeManager().getDataType("/Person");
		assertNotNull(personType);

		// non-custom storage
		tx(destinationProgram, () -> {
			destinationFunction.setReturnType(personType, SourceType.USER_DEFINED);
		});
	}

	private void setSourceFunctionThisPointerToPersonStructureWithCustomStorage() {
		tx(sourceProgram, () -> {
			sourceFunction.setCustomVariableStorage(true);

			Parameter param0 = sourceFunction.getParameter(0);
			Parameter param1 = sourceFunction.getParameter(1);
			param0.setDataType(param1.getDataType(), SourceType.USER_DEFINED);
		});

		DataType personType = sourceProgram.getDataTypeManager().getDataType("/Person");
		assertNotNull(personType);

		// custom storage
		tx(destinationProgram, () -> {
			destinationFunction.setCustomVariableStorage(true);
		});
	}

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

	private void checkSignatures(String expectedSrc, String expectedDest) {

		final String[] sourceStringBox = new String[1];
		final String[] destinationStringBox = new String[1];

		runSwing(() -> {
			sourceStringBox[0] = sourceFunction.getPrototypeString(false, false);
			destinationStringBox[0] = destinationFunction.getPrototypeString(false, false);
		});

		assertEquals("Source signature is not correct", expectedSrc, sourceStringBox[0]);
		assertEquals("Destination signature is not correct", expectedDest, destinationStringBox[0]);
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

	private void checkClassDataType(boolean shouldExist, boolean shouldBeNonEmpty) {

		Parameter srcParam = sourceFunction.getParameter(0);
		DataTypePath dataTypePath = srcParam.getDataType().getDataTypePath();

		ProgramBasedDataTypeManager dstDtman = destinationProgram.getDataTypeManager();
		DataType dstDataType = dstDtman.getDataType(dataTypePath);

		if (shouldExist) {
			assertTrue("Class type is not a pointer: " + dstDataType,
				dstDataType instanceof Pointer);

			Pointer dstDataTypePtr = (Pointer) dstDataType;
			DataType pointedToDataType = dstDataTypePtr.getDataType();
			assertTrue(pointedToDataType instanceof Structure);

			Structure struct = (Structure) pointedToDataType;
			assertNotNull(struct);

			if (shouldBeNonEmpty) {
				assertFalse("The structure should not be empty", struct.isNotYetDefined());
			}
			else {
				assertTrue("The structure is not empty as expected", struct.isNotYetDefined());
			}
		}
		else {
			assertNull(dstDataType);
		}
	}

	private void checkGadgetReturnType(boolean shouldBeNonEmpty) {

		DataType dt = sourceFunction.getReturnType();
		DataTypePath dataTypePath = dt.getDataTypePath();

		ProgramBasedDataTypeManager dstDtman = destinationProgram.getDataTypeManager();
		DataType dstDataType = dstDtman.getDataType(dataTypePath);

		assertTrue("Class type is not a pointer: " + dstDataType,
			dstDataType instanceof Pointer);

		Pointer dstDataTypePtr = (Pointer) dstDataType;
		DataType pointedToDataType = dstDataTypePtr.getDataType();
		assertTrue(pointedToDataType instanceof Structure);

		Structure struct = (Structure) pointedToDataType;
		assertNotNull(struct);

		if (shouldBeNonEmpty) {
			assertFalse("The return type structure should not be empty", struct.isNotYetDefined());
		}
		else {
			assertTrue("The return type structure is not empty as expected",
				struct.isNotYetDefined());
		}
	}

	private VTMarkupItem getFunctionSignatureMarkup(VTMatch match) {
		MatchInfo matchInfo = controller.getMatchInfo(match);
		Collection<VTMarkupItem> appliableMarkupItems =
			matchInfo.getAppliableMarkupItems(TaskMonitor.DUMMY);
		for (VTMarkupItem vtMarkupItem : appliableMarkupItems) {
			if (vtMarkupItem.getMarkupType() instanceof FunctionSignatureMarkupType) {
				return vtMarkupItem;
			}
		}
		return null;
	}

	@SuppressWarnings("deprecation") // don't show warning for test code
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
			program.setLanguage(language, compilerSpecID, true, TaskMonitor.DUMMY);
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

	private void runTask(VTSession vtSession, VtTask task) {
		int id = vtSession.startTransaction("test");
		try {
			task.run(TaskMonitor.DUMMY);
		}
		finally {
			vtSession.endTransaction(id, true);

			if (task.hasErrors()) {
				String errorDetails = task.getErrorDetails();
				fail("Error applying task: " + errorDetails);
			}
		}
	}
}
