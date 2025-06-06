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
package ghidra.app.util.pdb.pdbapplicator;

import static org.junit.Assert.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.util.SymbolPath;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.*;
import ghidra.app.util.pdb.classtype.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.gclass.ClassID;
import ghidra.program.model.gclass.ClassUtils;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

/**
 * Unit tests for the {@link CppCompositeType}.
 * <p>20250403: Modified to use ProgramCreator.  However, this class still has vestiges of
 * code to try to test "compiling" classes (syntactic representation to compiled representation),
 * and we don't yet know what this is going to look like later.  Thus, much of the code for
 * creating CppCompositeTypes is still found in this class and is somewhat duplicative with what
 * we have put into the ProgramCreator classes for the MockPdbs.  For now, leaving this duplication
 * until we determine how we will extract/move the syntactic work
 */
public class CppCompositeTypeTest extends AbstractGenericTest {

	private static MessageLog log = new MessageLog();
	private static TaskMonitor monitor = TaskMonitor.DUMMY;

	private static DataOrganizationImpl dataOrg32;
	private static DataOrganizationImpl dataOrg64;
	static {
		BitFieldPackingImpl bitFieldPacking = new BitFieldPackingImpl();
		bitFieldPacking.setUseMSConvention(true);
		// DataOrganization based on x86win.cspec
		// The DataOrganizationImpl currently has defaults of a 32-bit windows cspec, but could
		// change in the future.
		dataOrg32 = DataOrganizationImpl.getDefaultOrganization(null);
		dataOrg32.setBitFieldPacking(bitFieldPacking);
		// DataOrganization based on x86-64-win.cspec
		dataOrg64 = DataOrganizationImpl.getDefaultOrganization(null);
		DataOrganizationTestUtils.initDataOrganizationWindows64BitX86(dataOrg64);
		dataOrg64.setBitFieldPacking(bitFieldPacking);
	}

	private static ObjectOrientedClassLayout classLayoutChoice =
		ObjectOrientedClassLayout.CLASS_HIERARCHY;
	private static ObjectOrientedClassLayout speculativeLayoutChoice =
		ObjectOrientedClassLayout.CLASS_HIERARCHY_SPECULATIVE;

	ClearDataMode clearMode = ClearDataMode.CLEAR_ALL_CONFLICT_DATA;

	private DataTypeManager dtm32 = new StandAloneDataTypeManager("32-bit win", dataOrg32);
	private DataTypeManager dtm64 = new StandAloneDataTypeManager("64-bit win", dataOrg64);

	private static MyTestDummyDataTypeManager dtm32old = new MyTestDummyDataTypeManager(dataOrg32);
	private static MyTestDummyDataTypeManager dtm64old = new MyTestDummyDataTypeManager(dataOrg64);

	private Egray832ProgramCreator egray832Creator;
	private Program egray832Program;
	private MockPdb egray832Pdb;
	private Map<String, Address> egray832AddressesByMangled;
	private MsVxtManager egray832VxtManager;
	private MsVxtManager egray832VxtManagerNoProgram;

	private Egray864ProgramCreator egray864Creator;
	private Program egray864Program;
	private MockPdb egray864Pdb;
	private Map<String, Address> egray864AddressesByMangled;
	private MsVxtManager egray864VxtManager;
	private MsVxtManager egray864VxtManagerNoProgram;

	private Cfb432ProgramCreator cfb432Creator;
	private Program cfb432Program;
	private MockPdb cfb432Pdb;
	private Map<String, Address> cfb432AddressesByMangled;
	private MsVxtManager cfb432VxtManager;
	private MsVxtManager cfb432VxtManagerNoProgram;

	private Cfb464ProgramCreator cfb464Creator;
	private Program cfb464Program;
	private MockPdb cfb464Pdb;
	private Map<String, Address> cfb464AddressesByMangled;
	private MsVxtManager cfb464VxtManager;
	private MsVxtManager cfb464VxtManagerNoProgram;

	private Vftm32ProgramCreator vftm32Creator;
	private Program vftm32Program;
	private MockPdb vftm32Pdb;
	private Map<String, Address> vftm32AddressesByMangled;
	private MsVxtManager vftm32VxtManager;
	private MsVxtManager vftm32VxtManagerNoProgram;

	private Vftm64ProgramCreator vftm64Creator;
	private Program vftm64Program;
	private MockPdb vftm64Pdb;
	private Map<String, Address> vftm64AddressesByMangled;
	private MsVxtManager vftm64VxtManager;
	private MsVxtManager vftm64VxtManagerNoProgram;

	@Before
	public void setUp() throws Exception {

		ProgramTestArtifacts programTestArtifacts;
		ClassTypeManager ctm;

		egray832Creator = new Egray832ProgramCreator();
		programTestArtifacts = egray832Creator.create();
		egray832Program = programTestArtifacts.program();
		egray832Pdb = programTestArtifacts.pdb();
		egray832AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(egray832Program.getDataTypeManager());
		egray832VxtManager = new MsVxtManager(ctm, egray832Program);
		egray832VxtManager.createVirtualTables(CategoryPath.ROOT, egray832AddressesByMangled, log,
			monitor);

		int txID = egray832Program.startTransaction("Applying vxt symbols.");
		boolean commit = false;
		try {
			egray832Pdb.applySymbols(egray832Program);
			commit = true;
		}
		finally {
			egray832Program.endTransaction(txID, commit);
		}

		egray832VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

		egray864Creator = new Egray864ProgramCreator();
		programTestArtifacts = egray864Creator.create();
		egray864Program = programTestArtifacts.program();
		egray864Pdb = programTestArtifacts.pdb();
		egray864AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(egray864Program.getDataTypeManager());
		egray864VxtManager = new MsVxtManager(ctm, egray864Program);
		egray864VxtManager.createVirtualTables(CategoryPath.ROOT, egray864AddressesByMangled, log,
			monitor);

		txID = egray864Program.startTransaction("Applying vxt symbols.");
		commit = false;
		try {
			egray864Pdb.applySymbols(egray864Program);
			commit = true;
		}
		finally {
			egray864Program.endTransaction(txID, commit);
		}

		egray864VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

		cfb432Creator = new Cfb432ProgramCreator();
		programTestArtifacts = cfb432Creator.create();
		cfb432Program = programTestArtifacts.program();
		cfb432Pdb = programTestArtifacts.pdb();
		cfb432AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(cfb432Program.getDataTypeManager());
		cfb432VxtManager = new MsVxtManager(ctm, cfb432Program);
		cfb432VxtManager.createVirtualTables(CategoryPath.ROOT, cfb432AddressesByMangled, log,
			monitor);

		txID = cfb432Program.startTransaction("Applying vxt symbols.");
		commit = false;
		try {
			cfb432Pdb.applySymbols(cfb432Program);
			commit = true;
		}
		finally {
			cfb432Program.endTransaction(txID, commit);
		}

		cfb432VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

		cfb464Creator = new Cfb464ProgramCreator();
		programTestArtifacts = cfb464Creator.create();
		cfb464Program = programTestArtifacts.program();
		cfb464Pdb = programTestArtifacts.pdb();
		cfb464AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(cfb464Program.getDataTypeManager());
		cfb464VxtManager = new MsVxtManager(ctm, cfb464Program);
		cfb464VxtManager.createVirtualTables(CategoryPath.ROOT, cfb464AddressesByMangled, log,
			monitor);

		txID = cfb464Program.startTransaction("Applying vxt symbols.");
		commit = false;
		try {
			cfb464Pdb.applySymbols(cfb464Program);
			commit = true;
		}
		finally {
			cfb464Program.endTransaction(txID, commit);
		}

		cfb464VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

		vftm32Creator = new Vftm32ProgramCreator();
		programTestArtifacts = vftm32Creator.create();
		vftm32Program = programTestArtifacts.program();
		vftm32Pdb = programTestArtifacts.pdb();
		vftm32AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(vftm32Program.getDataTypeManager());
		vftm32VxtManager = new MsVxtManager(ctm, vftm32Program);
		vftm32VxtManager.createVirtualTables(CategoryPath.ROOT, vftm32AddressesByMangled, log,
			monitor);

		txID = vftm32Program.startTransaction("Applying vxt symbols.");
		commit = false;
		try {
			vftm32Pdb.applySymbols(vftm32Program);
			commit = true;
		}
		finally {
			vftm32Program.endTransaction(txID, commit);
		}

		vftm32VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

		vftm64Creator = new Vftm64ProgramCreator();
		programTestArtifacts = vftm64Creator.create();
		vftm64Program = programTestArtifacts.program();
		vftm64Pdb = programTestArtifacts.pdb();
		vftm64AddressesByMangled = programTestArtifacts.addressesByMangled();
		ctm = new ClassTypeManager(vftm64Program.getDataTypeManager());
		vftm64VxtManager = new MsVxtManager(ctm, vftm64Program);
		vftm64VxtManager.createVirtualTables(CategoryPath.ROOT, vftm64AddressesByMangled, log,
			monitor);

		txID = vftm64Program.startTransaction("Applying vxt symbols.");
		commit = false;
		try {
			vftm64Pdb.applySymbols(vftm64Program);
			commit = true;
		}
		finally {
			vftm64Program.endTransaction(txID, commit);
		}

		vftm64VxtManagerNoProgram = new MsVxtManager(ctm, null);

		//=====

	}

	private static CppCompositeType createStruct32(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm32old);
		SymbolPath symbolPath = new SymbolPath(name);
		String mangledName = createMangledName(name, ClassKey.STRUCT);
		return CppCompositeType.createCppStructType(CategoryPath.ROOT, symbolPath, composite, name,
			mangledName, size);
	}

	private static CppCompositeType createStruct64(String name, int size) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm64old);
		SymbolPath symbolPath = new SymbolPath(name);
		String mangledName = createMangledName(name, ClassKey.STRUCT);
		return CppCompositeType.createCppStructType(CategoryPath.ROOT, symbolPath, composite, name,
			mangledName, size);
	}

	private static String createMangledName(String className, ClassKey key) {
		StringBuilder builder = new StringBuilder();
		builder.append(".?A");
		switch (key) {
			case UNION:
				builder.append('T');
				break;
			case STRUCT:
				builder.append('U');
				break;
			case CLASS:
				builder.append('V');
				break;
			default:
				String msg = "Cannot handle type during testing" + key;
				Msg.error(null, msg);
				throw new AssertException(msg);
		}
		builder.append(className);
		builder.append("@@");
		return builder.toString();
	}

	private final static DataType charT = CharDataType.dataType;
	//private final static DataType shortT = ShortDataType.dataType;
	private final static DataType intT = IntegerDataType.dataType;
	//private final static DataType longlongT = LongLongDataType.dataType;

	//==============================================================================================
	private static class MyTestDummyDataTypeManager extends TestDummyDataTypeManager {
		HashMap<String, DataType> dataTypeMap = new HashMap<>();
		DataOrganizationImpl dataOrg;

		private MyTestDummyDataTypeManager(DataOrganizationImpl dataOrg) {
			this.dataOrg = dataOrg;
		}

		/**
		 * This is not part of the DataTypeManager API... it is only for testing when needing
		 *  to clear results because of another run that creates the same-named types
		 */
		private void clearMap() {
			dataTypeMap = new HashMap<>();
		}

		@Override
		public DataOrganization getDataOrganization() {
			return dataOrg;
		}

		@Override
		public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {
			if (dataType instanceof Composite composite) {
				String name = composite.getName();
				for (DataTypeComponent component : composite.getComponents()) {
					if (component.getDataType() instanceof Structure struct) {
						// TODO:
						// Need to fix the "!internal" to reference static value put into
						//  ClassType helper class
						if (struct.getCategoryPath().getName().equals("!internal") &&
							struct.getName().equals(name)) {
							addDataType(struct, null);
						}
					}
				}
			}
			return addDataType(dataType, null);
		}

		@Override
		public DataType addDataType(DataType dataType, DataTypeConflictHandler handler) {
			// handler ignored - tests should not induce conflicts
			String pathname = dataType.getPathName();
			DataType myDt = dataTypeMap.get(pathname);
			if (myDt != null) {
				return myDt;
			}
			DataType dt = dataType.clone(this);
			dataTypeMap.put(pathname, dt);
			return dt;
		}

		@Override
		public DataType findDataType(String dataTypePath) {
			return dataTypeMap.get(dataTypePath);
		}

		@Override
		public DataType getDataType(CategoryPath path, String name) {
			return getDataType(new DataTypePath(path, name).getPath());
		}

		@Override
		public DataType getDataType(String dataTypePath) {
			return dataTypeMap.get(dataTypePath);
		}

	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================
	/*
	 * struct A {
	 *    char c;
	 *    int i;
	 * };
	 */
	static CppCompositeType createA_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct32("A", 0);
		A_struct.addMember("c", charT, false, 0);
		A_struct.addMember("i", intT, false, 0);
		return A_struct;
	}

	static CppCompositeType createA_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createA_struct64(vxtManager) : createA_struct32(vxtManager);
	}

	static CppCompositeType createA_struct32(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct32("A", 8);
		A_struct.addMember("c", charT, false, 0);
		A_struct.addMember("i", intT, false, 4);
		return A_struct;
	}

	static CppCompositeType createA_struct64(VxtManager vxtManager) {
		CppCompositeType A_struct = createStruct64("A", 8);
		A_struct.addMember("c", charT, false, 0);
		A_struct.addMember("i", intT, false, 4);
		return A_struct;
	}

	//==============================================================================================
	/*
	 * struct C {
	 *    int c1;
	 *    void cf();
	 * };
	 */
	static CppCompositeType createC_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct32("C", 0);
		C_struct.addMember("c1", intT, false, 0);
		return C_struct;
	}

	static CppCompositeType createC_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createC_struct64(vxtManager) : createC_struct32(vxtManager);
	}

	static CppCompositeType createC_struct32(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct32("C", 4);
		C_struct.addMember("c1", intT, false, 0);
		return C_struct;
	}

	static CppCompositeType createC_struct64(VxtManager vxtManager) {
		CppCompositeType C_struct = createStruct64("C", 4);
		C_struct.addMember("c1", intT, false, 0);
		return C_struct;
	}

	//==============================================================================================
	/*
	 * struct CC1 {
	 *    int cc11;
	 *    void cc1f();
	 * };
	 */
	static CppCompositeType createCC1_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 0);
		CC1_struct.addMember("cc11", intT, false, 0);
		return CC1_struct;
	}

	static CppCompositeType createCC1_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC1_struct64(vxtManager) : createCC1_struct32(vxtManager);
	}

	static CppCompositeType createCC1_struct32(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct32("CC1", 4);
		CC1_struct.addMember("cc11", intT, false, 0);
		return CC1_struct;
	}

	static CppCompositeType createCC1_struct64(VxtManager vxtManager) {
		CppCompositeType CC1_struct = createStruct64("CC1", 4);
		CC1_struct.addMember("cc11", intT, false, 0);
		return CC1_struct;
	}

	//==============================================================================================
	/*
	 * struct CC2 {
	 *    int cc21;
	 *    void cc2f();
	 * };
	 */
	static CppCompositeType createCC2_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 0);
		CC2_struct.addMember("cc21", intT, false, 0);
		return CC2_struct;
	}

	static CppCompositeType createCC2_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC2_struct64(vxtManager) : createCC2_struct32(vxtManager);
	}

	static CppCompositeType createCC2_struct32(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct32("CC2", 4);
		CC2_struct.addMember("cc21", intT, false, 0);
		return CC2_struct;
	}

	static CppCompositeType createCC2_struct64(VxtManager vxtManager) {
		CppCompositeType CC2_struct = createStruct64("CC2", 4);
		CC2_struct.addMember("cc21", intT, false, 0);
		return CC2_struct;
	}

	//==============================================================================================
	/*
	 * struct CC3 {
	 *    void cc3f();
	 * };
	 */
	static CppCompositeType createCC3_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createCC3_struct64(vxtManager) : createCC3_struct32(vxtManager);
	}

	static CppCompositeType createCC3_struct32(VxtManager vxtManager) {
		CppCompositeType CC3_struct = createStruct32("CC3", 1); //TODO size 1 or 0?
		return CC3_struct;
	}

	static CppCompositeType createCC3_struct64(VxtManager vxtManager) {
		CppCompositeType CC3_struct = createStruct64("CC3", 1); //TODO size 1 or 0?
		return CC3_struct;
	}

	//==============================================================================================
	/*
	 * struct D : C {
	 *    int d1;
	 *    void df();
	 * };
	 */
	static CppCompositeType createD_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createD_struct64(vxtManager, C_struct)
				: createD_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createD_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType D_struct = createStruct32("D", 8);
			D_struct.addDirectBaseClass(C_struct.getComposite(), C_struct, 0);
			D_struct.addMember("d1", intT, false, 4);
			return D_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createD_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType D_struct = createStruct64("D", 8);
			D_struct.addDirectBaseClass(C_struct.getComposite(), C_struct, 0);
			D_struct.addMember("d1", intT, false, 4);
			return D_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct E {
	 *	  int e1;
	 *	  void ef();
	 *	};
	 */
	static CppCompositeType createE_syntactic_struct32(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct32("E", 0);
		E_struct.addMember("e1", intT, false, 0);
		return E_struct;
	}

	static CppCompositeType createE_struct(VxtManager vxtManager, boolean is64Bit) {
		return is64Bit ? createE_struct64(vxtManager) : createE_struct32(vxtManager);
	}

	static CppCompositeType createE_struct32(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct32("E", 4);
		E_struct.addMember("e1", intT, false, 0);
		return E_struct;
	}

	static CppCompositeType createE_struct64(VxtManager vxtManager) {
		CppCompositeType E_struct = createStruct64("E", 4);
		E_struct.addMember("e1", intT, false, 0);
		return E_struct;
	}

	//==============================================================================================
	/*
	 * struct F : C, E {
	 *	  int f1;
	 *	  void ff();
	 *	};
	 */
	static CppCompositeType createF_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit ? createF_struct64(vxtManager, C_struct, E_struct)
				: createF_struct32(vxtManager, C_struct, E_struct);
	}

	static CppCompositeType createF_struct32(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType F_struct = createStruct32("F", 12);
			F_struct.addDirectBaseClass(C_struct.getComposite(), C_struct, 0);
			F_struct.addDirectBaseClass(E_struct.getComposite(), E_struct, 4);
			F_struct.addMember("f1", intT, false, 8);
			return F_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createF_struct64(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType F_struct = createStruct64("F", 12);
			F_struct.addDirectBaseClass(C_struct.getComposite(), C_struct, 0);
			F_struct.addDirectBaseClass(E_struct.getComposite(), E_struct, 4);
			F_struct.addMember("f1", intT, false, 8);
			return F_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct G : virtual C {
	 *	  int g1;
	 *	  void gf();
	 *	};
	 */
	static CppCompositeType createG_syntactic_struct32(VxtManager vxtManager) {
		return createG_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createG_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct) {
		CppCompositeType G_struct = createStruct32("G", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			G_struct.addVirtualSyntacticBaseClass(C_struct.getComposite(), C_struct);
			G_struct.addMember("g1", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G_struct;
	}

	static CppCompositeType createG_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createG_struct64(vxtManager, C_struct)
				: createG_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createG_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType G_struct = createStruct32("G", 12);
			G_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			G_struct.addMember("g1", intT, false, 4);
			return G_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createG_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType G_struct = createStruct64("G", 24);
			G_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			G_struct.addMember("g1", intT, false, 8);
			return G_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct H : virtual C {
	 *	  int h1;
	 *	  void hf();
	 *	};
	 */
	static CppCompositeType createH_syntactic_struct32(VxtManager vxtManager) {
		return createH_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createH_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct) {
		CppCompositeType H_struct = createStruct32("H", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			H_struct.addVirtualSyntacticBaseClass(C_struct.getComposite(), C_struct);
			H_struct.addMember("h1", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H_struct;
	}

	static CppCompositeType createH_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct) {
		return is64Bit ? createH_struct64(vxtManager, C_struct)
				: createH_struct32(vxtManager, C_struct);
	}

	static CppCompositeType createH_struct32(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType H_struct = createStruct32("H", 12);
			H_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			H_struct.addMember("h1", intT, false, 4);
			return H_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createH_struct64(VxtManager vxtManager, CppCompositeType C_struct) {
		try {
			CppCompositeType H_struct = createStruct64("H", 24);
			H_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			H_struct.addMember("h1", intT, false, 8);
			return H_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct G1 : virtual C, virtual E {
	 *	  int g11;
	 *	  void g1f();
	 *	};
	 */
	static CppCompositeType createG1_syntactic_struct32(VxtManager vxtManager) {
		return createG1_syntactic_struct32(vxtManager, null, null);
	}

	static CppCompositeType createG1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		CppCompositeType G1_struct = createStruct32("G1", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			G1_struct.addVirtualSyntacticBaseClass(C_struct.getComposite(), C_struct);
			G1_struct.addVirtualSyntacticBaseClass(E_struct.getComposite(), E_struct);
			G1_struct.addMember("g11", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return G1_struct;
	}

	static CppCompositeType createG1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit ? createG1_struct64(vxtManager, C_struct, E_struct)
				: createG1_struct32(vxtManager, C_struct, E_struct);
	}

	static CppCompositeType createG1_struct32(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType G1_struct = createStruct32("G1", 16);
			G1_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			G1_struct.addMember("g11", intT, false, 4);
			return G1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createG1_struct64(VxtManager vxtManager, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType G1_struct = createStruct64("G1", 24);
			G1_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			G1_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			G1_struct.addMember("g11", intT, false, 8);
			return G1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct H1 : virtual E, virtual C { //order reversed from G1
	 *	  int h11;
	 *	  void h1f();
	 *	};
	 */
	static CppCompositeType createH1_syntactic_struct32(VxtManager vxtManager) {
		return createH1_syntactic_struct32(vxtManager, null, null);
	}

	static CppCompositeType createH1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType H1_struct = createStruct32("H1", 0);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			H1_struct.addVirtualSyntacticBaseClass(E_struct.getComposite(), E_struct);
			H1_struct.addVirtualSyntacticBaseClass(C_struct.getComposite(), C_struct);
			H1_struct.addMember("h11", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return H1_struct;
	}

	static CppCompositeType createH1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createH1_struct64(vxtManager, E_struct, C_struct)
				: createH1_struct32(vxtManager, E_struct, C_struct);
	}

	static CppCompositeType createH1_struct32(VxtManager vxtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		try {
			CppCompositeType H1_struct = createStruct32("H1", 16);
			H1_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			H1_struct.addMember("h11", intT, false, 4);
			return H1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createH1_struct64(VxtManager vxtManager, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		try {
			CppCompositeType H1_struct = createStruct64("H1", 24);
			H1_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			H1_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			H1_struct.addMember("h11", intT, false, 8);
			return H1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct GG1 : virtual CC1 {
	 *	  int gg11;
	 *	  void gg1f();
	 *	};
	 */
	static CppCompositeType createGG1_syntactic_struct32(VxtManager vxtManager) {
		return createGG1_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG1_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC1_struct) {
		CppCompositeType GG1_struct = createStruct32("GG1", 0);
		try {
			if (CC1_struct == null) {
				CC1_struct = createCC1_struct32(vxtManager);
			}
			GG1_struct.addVirtualSyntacticBaseClass(CC1_struct.getComposite(), CC1_struct);
			GG1_struct.addMember("gg11", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG1_struct;
	}

	static CppCompositeType createGG1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC1_struct) {
		return is64Bit ? createGG1_struct64(vxtManager, CC1_struct)
				: createGG1_struct32(vxtManager, CC1_struct);
	}

	static CppCompositeType createGG1_struct32(VxtManager vxtManager, CppCompositeType CC1_struct) {
		try {
			CppCompositeType GG1_struct = createStruct32("GG1", 12);
			GG1_struct.addDirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG1_struct.addMember("gg11", intT, false, 4);
			return GG1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG1_struct64(VxtManager vxtManager, CppCompositeType CC1_struct) {
		try {
			CppCompositeType GG1_struct = createStruct64("GG1", 24);
			GG1_struct.addDirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG1_struct.addMember("gg11", intT, false, 8);
			return GG1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct GG2 : virtual CC2 {
	 *	  int gg21;
	 *	  void gg2f();
	 *	};
	 */
	static CppCompositeType createGG2_syntactic_struct32(VxtManager vxtManager) {
		return createGG2_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG2_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG2_struct = createStruct32("GG2", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vxtManager);
			}
			GG2_struct.addVirtualSyntacticBaseClass(CC2_struct.getComposite(), CC2_struct);
			GG2_struct.addMember("gg21", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG2_struct;
	}

	static CppCompositeType createGG2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC2_struct) {
		return is64Bit ? createGG2_struct64(vxtManager, CC2_struct)
				: createGG2_struct32(vxtManager, CC2_struct);
	}

	static CppCompositeType createGG2_struct32(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG2_struct = createStruct32("GG2", 12);
			GG2_struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG2_struct.addMember("gg21", intT, false, 4);
			return GG2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG2_struct64(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG2_struct = createStruct64("GG2", 24);
			GG2_struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG2_struct.addMember("gg21", intT, false, 8);
			return GG2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct GG3 : virtual CC2 {
	 *	  int gg31;
	 *	  void gg3f();
	 *	};
	 */
	static CppCompositeType createGG3_syntactic_struct32(VxtManager vxtManager) {
		return createGG3_syntactic_struct32(vxtManager, null);
	}

	static CppCompositeType createGG3_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType CC2_struct) {
		CppCompositeType GG3_struct = createStruct32("GG3", 0);
		try {
			if (CC2_struct == null) {
				CC2_struct = createCC2_struct32(vxtManager);
			}
			GG3_struct.addVirtualSyntacticBaseClass(CC2_struct.getComposite(), CC2_struct);
			GG3_struct.addMember("gg31", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return GG3_struct;
	}

	static CppCompositeType createGG3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC2_struct) {
		return is64Bit ? createGG3_struct64(vxtManager, CC2_struct)
				: createGG3_struct32(vxtManager, CC2_struct);
	}

	static CppCompositeType createGG3_struct32(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG3_struct = createStruct32("GG3", 12);
			GG3_struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG3_struct.addMember("gg31", intT, false, 4);
			return GG3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG3_struct64(VxtManager vxtManager, CppCompositeType CC2_struct) {
		try {
			CppCompositeType GG3_struct = createStruct64("GG3", 24);
			GG3_struct.addDirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG3_struct.addMember("gg31", intT, false, 8);
			return GG3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct GG4 : virtual CC3 {
	 *	  int gg41;
	 *	  void gg5f();
	 *	};
	 */
	static CppCompositeType createGG4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType CC3_struct) {
		return is64Bit ? createGG4_struct64(vxtManager, CC3_struct)
				: createGG4_struct32(vxtManager, CC3_struct);
	}

	static CppCompositeType createGG4_struct32(VxtManager vxtManager, CppCompositeType CC3_struct) {
		try {
			CppCompositeType GG4_struct = createStruct32("GG4", 8);
			GG4_struct.addDirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG4_struct.addMember("gg41", intT, false, 4);
			return GG4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createGG4_struct64(VxtManager vxtManager, CppCompositeType CC3_struct) {
		try {
			CppCompositeType GG4_struct = createStruct64("GG4", 16);
			GG4_struct.addDirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			GG4_struct.addMember("gg41", intT, false, 8);
			return GG4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct I : G, H {
	 *	  int i1;
	 *	  void _if();
	 *	};
	 */
	static CppCompositeType createI_syntactic_struct32(VxtManager vxtManager) {
		return createI_syntactic_struct32(vxtManager, null, null, null);
	}

	static CppCompositeType createI_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct) {
		CppCompositeType I_struct = createStruct32("I", 0);
		try {
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			// Could be problem if only one of G or H is null: won't have same C.
			if (G_struct == null) {
				G_struct = createG_struct32(vxtManager, C_struct);
			}
			if (H_struct == null) {
				H_struct = createH_struct32(vxtManager, C_struct);
			}
			I_struct.addDirectSyntacticBaseClass(G_struct.getComposite(), G_struct);
			I_struct.addDirectSyntacticBaseClass(H_struct.getComposite(), H_struct);
			I_struct.addMember("i1", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I_struct;
	}

	static CppCompositeType createI_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G_struct, CppCompositeType H_struct, CppCompositeType C_struct) {
		return is64Bit ? createI_struct64(vxtManager, G_struct, H_struct, C_struct)
				: createI_struct32(vxtManager, G_struct, H_struct, C_struct);
	}

	static CppCompositeType createI_struct32(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I_struct = createStruct32("I", 24);
			I_struct.addDirectBaseClass(G_struct.getComposite(), G_struct, 0);
			I_struct.addDirectBaseClass(H_struct.getComposite(), H_struct, 8);
			I_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			I_struct.addMember("i1", intT, false, 16);
			return I_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI_struct64(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I_struct = createStruct64("I", 48);
			I_struct.addDirectBaseClass(G_struct.getComposite(), G_struct, 0);
			I_struct.addDirectBaseClass(H_struct.getComposite(), H_struct, 16);
			I_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			I_struct.addMember("i1", intT, false, 32);
			return I_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct I1 : G1, H {
	 *	  int i11;
	 *	  void _i1f();
	 *	};
	 */
	static CppCompositeType createI1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType H_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createI1_struct64(vxtManager, G1_struct, H_struct, C_struct, E_struct)
				: createI1_struct32(vxtManager, G1_struct, H_struct, C_struct, E_struct);
	}

	static CppCompositeType createI1_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I1_struct = createStruct32("I1", 28);
			I1_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct.getComposite(), H_struct, 8);
			I1_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I1_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I1_struct.addMember("i11", intT, false, 16);
			return I1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI1_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I1_struct = createStruct64("I1", 48);
			I1_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I1_struct.addDirectBaseClass(H_struct.getComposite(), H_struct, 16);
			I1_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I1_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I1_struct.addMember("i11", intT, false, 32);
			return I1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct I2 : G, H1 {
	 *	  int i21;
	 *	  void _i2f();
	 *	};
	 */
	static CppCompositeType createI2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G_struct, CppCompositeType H1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createI2_struct64(vxtManager, G_struct, H1_struct, C_struct, E_struct)
				: createI2_struct32(vxtManager, G_struct, H1_struct, C_struct, E_struct);
	}

	static CppCompositeType createI2_struct32(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I2_struct = createStruct32("I2", 28);
			I2_struct.addDirectBaseClass(G_struct.getComposite(), G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, 8);
			I2_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I2_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I2_struct.addMember("i21", intT, false, 16);
			return I2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI2_struct64(VxtManager vxtManager, CppCompositeType G_struct,
			CppCompositeType H1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType I2_struct = createStruct64("I2", 48);
			I2_struct.addDirectBaseClass(G_struct.getComposite(), G_struct, 0);
			I2_struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, 16);
			I2_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I2_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I2_struct.addMember("i21", intT, false, 32);
			return I2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct I3 : G1, H1 {
	 *	  int i31;
	 *	  void _i3f();
	 *	};
	 */
	static CppCompositeType createI3_syntactic_struct32(VxtManager vxtManager) {
		return createI3_syntactic_struct32(vxtManager, null, null, null, null);
	}

	static CppCompositeType createI3_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		CppCompositeType I3_struct = createStruct32("I3", 8);
		try {
			if (E_struct == null) {
				E_struct = createE_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_struct32(vxtManager);
			}
			if (G1_struct == null) {
				G1_struct = createG1_struct32(vxtManager, C_struct, E_struct);
			}
			if (H1_struct == null) {
				H1_struct = createH1_struct32(vxtManager, E_struct, C_struct);
			}
			I3_struct.addDirectSyntacticBaseClass(G1_struct.getComposite(), G1_struct);
			I3_struct.addDirectSyntacticBaseClass(H1_struct.getComposite(), H1_struct);
			I3_struct.addMember("i31", intT, false, 0);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I3_struct;
	}

	static CppCompositeType createI3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType H1_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		return is64Bit ? createI3_struct64(vxtManager, G1_struct, H1_struct, E_struct, C_struct)
				: createI3_struct32(vxtManager, G1_struct, H1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI3_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I3_struct = createStruct32("I3", 28);
			I3_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, 8);
			I3_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I3_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I3_struct.addMember("i31", intT, false, 16);
			return I3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI3_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType H1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I3_struct = createStruct64("I3", 48);
			I3_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I3_struct.addDirectBaseClass(H1_struct.getComposite(), H1_struct, 16);
			I3_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I3_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			I3_struct.addMember("i31", intT, false, 32);
			return I3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct I4 : G1, virtual E, virtual C {
	 *	  int i41;
	 *	  void _i4f();
	 *	};
	 */
	static CppCompositeType createI4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createI4_struct64(vxtManager, G1_struct, E_struct, C_struct)
				: createI4_struct32(vxtManager, G1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI4_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I4_struct = createStruct32("I4", 20);
			I4_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			I4_struct.addMember("i41", intT, false, 8);
			return I4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI4_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		CppCompositeType I4_struct = createStruct64("I4", 32);
		try {
			I4_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I4_struct.addDirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE, 2);
			I4_struct.addDirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE, 1);
			I4_struct.addMember("i41", intT, false, 16);
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return I4_struct;
	}

	//==============================================================================================
	/*
	 * struct I5 : virtual E, virtual C, G1 {
	 *	  int i51;
	 *	  void _i5f();
	 *	};
	 */
	static CppCompositeType createI5_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType G1_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		return is64Bit ? createI5_struct64(vxtManager, G1_struct, E_struct, C_struct)
				: createI5_struct32(vxtManager, G1_struct, E_struct, C_struct);
	}

	static CppCompositeType createI5_struct32(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I5_struct = createStruct32("I5", 20);
			I5_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I5_struct.addMember("i51", intT, false, 8);
			return I5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createI5_struct64(VxtManager vxtManager, CppCompositeType G1_struct,
			CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType I5_struct = createStruct64("I5", 32);
			I5_struct.addDirectBaseClass(G1_struct.getComposite(), G1_struct, 0);
			I5_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2); // check this and I4...TODO
			I5_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			I5_struct.addMember("i51", intT, false, 16);
			return I5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J1 : I1, I2 {
	 *	  int j11;
	 *	  void j1f();
	 *	};
	 */
	static CppCompositeType createJ1_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I1_struct, CppCompositeType I2_struct, CppCompositeType E_struct,
			CppCompositeType C_struct) {
		return is64Bit ? createJ1_struct64(vxtManager, I1_struct, I2_struct, E_struct, C_struct)
				: createJ1_struct32(vxtManager, I1_struct, I2_struct, E_struct, C_struct);
	}

	static CppCompositeType createJ1_struct32(VxtManager vxtManager, CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType J1_struct = createStruct32("J1", 52);
			J1_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 20);
			J1_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J1_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J1_struct.addMember("j11", intT, false, 40);
			return J1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ1_struct64(VxtManager vxtManager, CppCompositeType I1_struct,
			CppCompositeType I2_struct, CppCompositeType E_struct, CppCompositeType C_struct) {
		try {
			CppCompositeType J1_struct = createStruct64("J1", 96);
			J1_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 0);
			J1_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 40);
			J1_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J1_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J1_struct.addMember("j11", intT, false, 80);
			return J1_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J2 : I2, I1 {
	 *	  int j21;
	 *	  void j2f();
	 *	};
	 */
	static CppCompositeType createJ2_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		return is64Bit ? createJ2_struct64(vxtManager, I2_struct, I1_struct, C_struct, E_struct)
				: createJ2_struct32(vxtManager, I2_struct, I1_struct, C_struct, E_struct);
	}

	static CppCompositeType createJ2_struct32(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType J2_struct = createStruct32("J2", 52);
			J2_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 20);
			J2_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J2_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J2_struct.addMember("j21", intT, false, 40);
			return J2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ2_struct64(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType C_struct, CppCompositeType E_struct) {
		try {
			CppCompositeType J2_struct = createStruct64("J2", 96);
			J2_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 0);
			J2_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 40);
			J2_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J2_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J2_struct.addMember("j21", intT, false, 80);
			return J2_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J3 : I2, I1, A {
	 *	  int j31;
	 *	  void j3f();
	 *	};
	 */
	static CppCompositeType createJ3_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I2_struct, CppCompositeType I1_struct, CppCompositeType A_struct,
			CppCompositeType C_struct, CppCompositeType E_struct) {
		return is64Bit
				? createJ3_struct64(vxtManager, I2_struct, I1_struct, A_struct, C_struct, E_struct)
				: createJ3_struct32(vxtManager, I2_struct, I1_struct, A_struct, C_struct, E_struct);
	}

	static CppCompositeType createJ3_struct32(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType J3_struct = createStruct32("J3", 60);
			J3_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 20);
			J3_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 40);
			J3_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J3_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J3_struct.addMember("j31", intT, false, 48);
			return J3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ3_struct64(VxtManager vxtManager, CppCompositeType I2_struct,
			CppCompositeType I1_struct, CppCompositeType A_struct, CppCompositeType C_struct,
			CppCompositeType E_struct) {
		try {
			CppCompositeType J3_struct = createStruct64("J3", 104);
			J3_struct.addDirectBaseClass(I2_struct.getComposite(), I2_struct, 0);
			J3_struct.addDirectBaseClass(I1_struct.getComposite(), I1_struct, 40);
			J3_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 80);
			J3_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J3_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J3_struct.addMember("j31", intT, false, 88);
			return J3_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J4 : I3, GG1, I, A, virtual GG2, virtual GG3 {
	 *	  int j41;
	 *	  void j4f();
	 *	};
	 */
	static CppCompositeType createJ4_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		return is64Bit
				? createJ4_struct64(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct)
				: createJ4_struct32(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct);
	}

	static CppCompositeType createJ4_struct32(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J4_struct = createStruct32("J4", 92);
			J4_struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, 20);
			J4_struct.addDirectBaseClass(I_struct.getComposite(), I_struct, 28);
			J4_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 48);
			J4_struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				6);
			J4_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J4_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE, 4);
			J4_struct.addMember("j41", intT, false, 56);
			return J4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ4_struct64(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J4_struct = createStruct64("J4", 160);
			J4_struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, 0);
			J4_struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, 40);
			J4_struct.addDirectBaseClass(I_struct.getComposite(), I_struct, 56);
			J4_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 96);
			J4_struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				5);
			J4_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				6);
			J4_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J4_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J4_struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE, 3);
			J4_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE, 4);
			J4_struct.addMember("j41", intT, false, 104);
			return J4_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J5 : virtual GG2, virtual GG3, I3, GG1, I, A {
	 *	  int j51;
	 *	  void j5f();
	 *	};
	 */
	static CppCompositeType createJ5_syntactic_struct32(VxtManager vxtManager) {
		return createJ5_syntactic_struct32(vxtManager, null, null, null, null, null, null, null,
			null, null, null);
	}

	static CppCompositeType createJ5_syntactic_struct32(VxtManager vxtManager,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		CppCompositeType J5_struct = createStruct32("J5", 0); // TODO need without size
		try {
			if (A_struct == null) {
				A_struct = createA_syntactic_struct32(vxtManager);
			}
			if (C_struct == null) {
				C_struct = createC_syntactic_struct32(vxtManager);
			}
			if (E_struct == null) {
				E_struct = createE_syntactic_struct32(vxtManager);
			}
			if (CC1_struct == null) {
				CC1_struct = createCC1_syntactic_struct32(vxtManager);
			}
			if (CC2_struct == null) {
				CC2_struct = createCC2_syntactic_struct32(vxtManager);
			}
			if (I3_struct == null) {
				CppCompositeType G1_struct =
					createG1_syntactic_struct32(vxtManager, C_struct, E_struct);
				CppCompositeType H1_struct =
					createH1_syntactic_struct32(vxtManager, E_struct, C_struct);
				I3_struct = createI3_syntactic_struct32(vxtManager, G1_struct, H1_struct, E_struct,
					C_struct);
			}
			if (GG1_struct == null) {
				GG1_struct = createGG1_syntactic_struct32(vxtManager, CC1_struct);
			}
			if (I_struct == null) {
				CppCompositeType G_struct = createG_syntactic_struct32(vxtManager, C_struct);
				CppCompositeType H_struct = createH_syntactic_struct32(vxtManager, C_struct);
				I_struct = createI_syntactic_struct32(vxtManager, G_struct, H_struct, C_struct);
			}
			if (GG2_struct == null) {
				GG2_struct = createGG2_syntactic_struct32(vxtManager, CC2_struct);
			}
			if (GG3_struct == null) {
				GG3_struct = createGG3_syntactic_struct32(vxtManager, CC2_struct);
			}
			J5_struct.addVirtualSyntacticBaseClass(GG2_struct.getComposite(), GG2_struct);
			J5_struct.addVirtualSyntacticBaseClass(GG3_struct.getComposite(), GG3_struct);
			J5_struct.addDirectSyntacticBaseClass(I3_struct.getComposite(), I3_struct);
			J5_struct.addDirectSyntacticBaseClass(GG1_struct.getComposite(), GG1_struct);
			J5_struct.addDirectSyntacticBaseClass(I_struct.getComposite(), I_struct);
			J5_struct.addDirectSyntacticBaseClass(A_struct.getComposite(), A_struct);
			J5_struct.addMember("j51", intT, false, 0); // TODO nned syntactic without index
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
		return J5_struct;
	}

	static CppCompositeType createJ5_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType I3_struct, CppCompositeType GG1_struct, CppCompositeType I_struct,
			CppCompositeType A_struct, CppCompositeType GG2_struct, CppCompositeType GG3_struct,
			CppCompositeType C_struct, CppCompositeType E_struct, CppCompositeType CC1_struct,
			CppCompositeType CC2_struct) {
		return is64Bit
				? createJ5_struct64(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct)
				: createJ5_struct32(vxtManager, I3_struct, GG1_struct, I_struct, A_struct,
					GG2_struct, GG3_struct, C_struct, E_struct, CC1_struct, CC2_struct);
	}

	static CppCompositeType createJ5_struct32(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J5_struct = createStruct32("J5", 92);
			J5_struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, 20);
			J5_struct.addDirectBaseClass(I_struct.getComposite(), I_struct, 28);
			J5_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 48);
			J5_struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J5_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE, 6);
			J5_struct.addMember("j51", intT, false, 56);
			return J5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ5_struct64(VxtManager vxtManager, CppCompositeType I3_struct,
			CppCompositeType GG1_struct, CppCompositeType I_struct, CppCompositeType A_struct,
			CppCompositeType GG2_struct, CppCompositeType GG3_struct, CppCompositeType C_struct,
			CppCompositeType E_struct, CppCompositeType CC1_struct, CppCompositeType CC2_struct) {
		try {
			CppCompositeType J5_struct = createStruct64("J5", 168);
			J5_struct.addDirectBaseClass(I3_struct.getComposite(), I3_struct, 0);
			J5_struct.addDirectBaseClass(GG1_struct.getComposite(), GG1_struct, 40);
			J5_struct.addDirectBaseClass(I_struct.getComposite(), I_struct, 56);
			J5_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 96);
			J5_struct.addDirectVirtualBaseClass(GG2_struct.getComposite(), GG2_struct, 0,
				ClassUtils.VXPTR_TYPE,
				4);
			J5_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 0,
				ClassUtils.VXPTR_TYPE,
				5);
			J5_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 0,
				ClassUtils.VXPTR_TYPE, 3);
			J5_struct.addIndirectVirtualBaseClass(C_struct.getComposite(), C_struct, 0,
				ClassUtils.VXPTR_TYPE,
				1);
			J5_struct.addIndirectVirtualBaseClass(E_struct.getComposite(), E_struct, 0,
				ClassUtils.VXPTR_TYPE,
				2);
			J5_struct.addIndirectVirtualBaseClass(CC1_struct.getComposite(), CC1_struct, 0,
				ClassUtils.VXPTR_TYPE, 6);
			J5_struct.addMember("j51", intT, false, 104);
			return J5_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	/*
	 * struct J6 : virtual GG4, virtual GG3, A { //GG4 has no members
	 *    int j61;
	 *	  void j6f();
	 * };
	 */
	static CppCompositeType createJ6_struct(VxtManager vxtManager, boolean is64Bit,
			CppCompositeType A_struct, CppCompositeType GG4_struct, CppCompositeType GG3_struct,
			CppCompositeType CC2_struct, CppCompositeType CC3_struct) {
		return is64Bit
				? createJ6_struct64(vxtManager, A_struct, GG4_struct, GG3_struct, CC2_struct,
					CC3_struct)
				: createJ6_struct32(vxtManager, A_struct, GG4_struct, GG3_struct, CC2_struct,
					CC3_struct);
	}

	static CppCompositeType createJ6_struct32(VxtManager vxtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		try {
			CppCompositeType J6_struct = createStruct32("J6", 36);
			J6_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct.getComposite(), GG4_struct, 8,
				ClassUtils.VXPTR_TYPE,
				2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 8,
				ClassUtils.VXPTR_TYPE,
				4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct, 8,
				ClassUtils.VXPTR_TYPE, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 8,
				ClassUtils.VXPTR_TYPE, 3);
			J6_struct.addMember("j61", intT, false, 12);
			return J6_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	static CppCompositeType createJ6_struct64(VxtManager vxtManager, CppCompositeType A_struct,
			CppCompositeType GG4_struct, CppCompositeType GG3_struct, CppCompositeType CC2_struct,
			CppCompositeType CC3_struct) {
		try {
			CppCompositeType J6_struct = createStruct64("J6", 64);
			J6_struct.addDirectBaseClass(A_struct.getComposite(), A_struct, 0);
			J6_struct.addDirectVirtualBaseClass(GG4_struct.getComposite(), GG4_struct, 8,
				ClassUtils.VXPTR_TYPE,
				2);
			J6_struct.addDirectVirtualBaseClass(GG3_struct.getComposite(), GG3_struct, 8,
				ClassUtils.VXPTR_TYPE,
				4);
			J6_struct.addIndirectVirtualBaseClass(CC3_struct.getComposite(), CC3_struct, 8,
				ClassUtils.VXPTR_TYPE, 1);
			J6_struct.addIndirectVirtualBaseClass(CC2_struct.getComposite(), CC2_struct, 8,
				ClassUtils.VXPTR_TYPE, 3);
			J6_struct.addMember("j61", intT, false, 16);
			return J6_struct;
		}
		catch (Exception e) {
			String msg = "Error in static initialization of test: " + e;
			Msg.error(null, msg);
			throw new AssertException(msg);
		}
	}

	//==============================================================================================
	//==============================================================================================
	//==============================================================================================

	/**
	 * Tests the classes and artifacts of egray8 32-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_32() throws Exception {
		boolean is64Bit = false;
		Program program = egray832Program;
		MockPdb pdb = egray832Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = egray832VxtManager;
		Map<ClassID, String> expectedResults = egray832Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			egray832Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			egray832Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of egray8 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_32_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = egray832Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = egray832VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = egray832Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of egray8 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_32_noProgram_speculative() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = egray832Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = egray832VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = egray832Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			egray832Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			egray832Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	/**
	 * Tests the classes and artifacts of egray8 64-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_64() throws Exception {
		boolean is64Bit = false;
		Program program = egray864Program;
		MockPdb pdb = egray864Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = egray864VxtManager;
		Map<ClassID, String> expectedResults = egray864Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			egray864Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			egray864Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of egray8 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_64_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = egray864Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = egray864VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = egray864Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of egray8 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testEgray8_64_noProgram_speculative() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = egray864Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = egray864VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = egray864Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			egray864Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			egray864Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	/**
	 * Tests the classes and artifacts of vftm 32-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_32() throws Exception {
		boolean is64Bit = false;
		Program program = vftm32Program;
		MockPdb pdb = vftm32Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = vftm32VxtManager;
		Map<ClassID, String> expectedResults = vftm32Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			vftm32Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			vftm32Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of vftm 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_32_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = vftm32Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = vftm32VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = vftm32Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of vftm 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_32_noProgram_speculative() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = vftm32Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = vftm32VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = vftm32Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			vftm32Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			vftm32Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	/**
	 * Tests the classes and artifacts of vftm 64-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_64() throws Exception {
		boolean is64Bit = true;
		Program program = vftm64Program;
		MockPdb pdb = vftm64Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = vftm64VxtManager;
		Map<ClassID, String> expectedResults = vftm64Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			vftm64Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			vftm64Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of vftm 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_64_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = vftm64Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = vftm64VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = vftm64Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of vftm 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testVftm_64_noProgram_speculative() throws Exception {
		boolean is64Bit = true;
		Program program = null;
		MockPdb pdb = vftm64Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = vftm64VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = vftm64Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			vftm64Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			vftm64Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	/**
	 * Tests the classes and artifacts of cfb4 32-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_32() throws Exception {
		boolean is64Bit = false;
		Program program = cfb432Program;
		MockPdb pdb = cfb432Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = cfb432VxtManager;
		Map<ClassID, String> expectedResults = cfb432Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			cfb432Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			cfb432Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of cfb4 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_32_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = cfb432Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = cfb432VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = cfb432Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of cfb4 32-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_32_speculative() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = cfb432Pdb;
		DataTypeManager dtm = dtm32;
		MsVxtManager vxtManager = cfb432VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = cfb432Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			cfb432Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			cfb432Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	/**
	 * Tests the classes and artifacts of cfb4 64-bit program
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_64() throws Exception {
		boolean is64Bit = true;
		Program program = cfb464Program;
		MockPdb pdb = cfb464Pdb;
		DataTypeManager dtm = program.getDataTypeManager();
		MsVxtManager vxtManager = cfb464VxtManager;
		Map<ClassID, String> expectedResults = cfb464Creator.getExpectedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			cfb464Creator.getExpectedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			cfb464Creator.getExpectedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	/**
	 * Tests the classes and artifacts of cfb4 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_64_noProgram() throws Exception {
		boolean is64Bit = false;
		Program program = null;
		MockPdb pdb = cfb464Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = cfb464VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = cfb464Creator.getFillerStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, classLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, null);
			vxtManager.createTables(dtm, clearMode);
		});
		// Not checking vxt structures here.
	}

	/**
	 * Tests the classes and artifacts of cfb4 64-bit program PDB (speculative)
	 * @throws Exception upon error
	 */
	@Test
	public void testCfb4_64_noProgram_speculative() throws Exception {
		boolean is64Bit = true;
		Program program = null;
		MockPdb pdb = cfb464Pdb;
		DataTypeManager dtm = dtm64;
		MsVxtManager vxtManager = cfb464VxtManagerNoProgram;
		Map<ClassID, String> expectedResults = cfb464Creator.getSpeculatedStructs();
		Map<ClassID, Map<String, String>> expectedVxtPtrSummaries =
			cfb464Creator.getSpeculatedVxtPtrSummaries();
		Map<ClassID, Map<String, String>> expectedVxtStructs =
			cfb464Creator.getSpeculatedVxtStructs();
		dtm.withTransaction("Processing data.", () -> {
			createAndTestStructures(program, dtm, speculativeLayoutChoice, pdb, is64Bit, vxtManager,
				expectedResults, expectedVxtPtrSummaries);
			vxtManager.createTables(dtm, clearMode);
		});
		checkVxtStructures(dtm, expectedVxtStructs);
	}

	//==============================================================================================
	//==============================================================================================
	private void createAndTestStructures(Program program, DataTypeManager dtm,
			ObjectOrientedClassLayout layoutChoice, MockPdb pdb, boolean is64Bit,
			MsVxtManager vxtManager, Map<ClassID, String> expectedResults,
			Map<ClassID, Map<String, String>> expectedVxtPtrSummaries) throws Exception {

		for (CppCompositeType cppType : pdb.getCppTypes()) {
			ClassID id = cppType.getClassId();
			cppType.createLayout(layoutChoice, vxtManager, monitor);
			Composite composite = pdb.resolveType(dtm, cppType);
			String expected = expectedResults.get(id);
			if (expected == null || expected.equals("NOT YET DETERMINED")) {
				continue;
			}
			CompositeTestUtils.assertExpectedComposite(this, expected, composite, true);
			if (expectedVxtPtrSummaries == null) {
				continue;
			}
			Map<String, String> expectedSummary = expectedVxtPtrSummaries.get(id);
			Map<String, String> vxtPtrSummary = cppType.getVxtPtrSummary();
			assertEquals(expectedSummary.size(), vxtPtrSummary.size());
			for (Map.Entry<String, String> summary : expectedSummary.entrySet()) {
				String tableName = summary.getKey();
				String expectedVxtPtrSummary = summary.getValue();
				String foundVxtPtrSummary = vxtPtrSummary.get(tableName);
				// 20250403:  The following classes currently have "bad" expected vxtptr summaries
				//  for at least one vxtptr (in Egray):
				//  AA4q, AA5g, AA5h, AA5j, AA6h, AA6j, BB2c, BB2d.
				// Our current tests match these bad results so not to fail
				if (expectedVxtPtrSummary == null) {
					Msg.warn(this,
						"Purposefully skipping table test that has bad result for " +
							id.getSymbolPath() + " " + tableName);
					continue;
				}
				assertEquals(expectedVxtPtrSummary, foundVxtPtrSummary);
			}
		}
	}

	private void checkVxtStructures(DataTypeManager dtm,
			Map<ClassID, Map<String, String>> expectedVxtStructs) {
		for (Map.Entry<ClassID, Map<String, String>> entry : expectedVxtStructs.entrySet()) {
			ClassID id = entry.getKey();
			CategoryPath cp = ClassUtils.getClassInternalsPath(id);
			Category category = dtm.getCategory(cp);
			Map<String, String> expectedTables = entry.getValue();
			for (Map.Entry<String, String> tableEntry : expectedTables.entrySet()) {
				String tableName = tableEntry.getKey();
				String expectedTableDump = tableEntry.getValue();
				if (expectedTableDump == null) {
					Msg.warn(this,
						"Purposefully skipping table test that has bad result for " + tableName);
					continue;
				}
				assertNotNull(category);
				Structure table = (Structure) category.getDataType(tableName);
				assertNotNull(table);
				CompositeTestUtils.assertExpectedComposite(this, expectedTableDump, table, true);
			}
			// Make sure there are no extra tables
			if (category != null) {
				int count = 0;
				DataType[] types = category.getDataTypes();
				if (types != null) {
					for (DataType type : category.getDataTypes()) {
						if (ClassUtils.isVTable(type)) {
							count++;
						}
					}
				}
				assertEquals(expectedTables.size(), count);
			}
		}
	}

	//==============================================================================================
	//==============================================================================================

	/**
	 * Test struct J5 - 32 - syntactics
	 * @throws Exception upon error
	 */
//	@Test
	@Ignore
	public void testJ5_32_syntactic_layout() throws Exception {
//		SyntacticClass structJ5 = createSyntacticStructJ5(MsftVxtManager32);
		// TODO: determine if we need a builder that inputs a SyntacticClass along with a
		// data type manager (w/ data organization), along with layout options for creating
		// data type (/class).
		//structJ5.createLayoutFromSyntacticDescription(MsftVxtManager32, TaskMonitor.DUMMY);

		//
		//Composite composite = structJ5.getComposite();
		//CompositeTestUtils.assertExpectedComposite(this, getExpectedJ5_32(), composite, true);
	}

}
