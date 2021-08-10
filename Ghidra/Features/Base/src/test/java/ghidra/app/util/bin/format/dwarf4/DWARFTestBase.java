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
package ghidra.app.util.bin.format.dwarf4;

import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFAttribute.*;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFEncoding.*;
import static ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.After;
import org.junit.Before;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFSourceLanguage;
import ghidra.app.util.bin.format.dwarf4.encoding.DWARFTag;
import ghidra.app.util.bin.format.dwarf4.next.*;
import ghidra.app.util.bin.format.dwarf4.next.sectionprovider.NullSectionProvider;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for unit tests needing DWARF DIEs.  Provides 2 DWARF compile-units and helper
 * methods to create DIE records.
 */
public class DWARFTestBase extends AbstractGhidraHeadedIntegrationTest {

	protected static final long BaseAddress = 0x400;

	protected ProgramDB program;
	protected AddressSpace space;
	protected DataTypeManagerDB dataMgr;
	protected DataTypeManager builtInDTM;
	protected int transactionID;
	protected TaskMonitor monitor = TaskMonitor.DUMMY;

	protected DWARFImportOptions importOptions;
	protected DWARFProgram dwarfProg;
	protected MockDWARFCompilationUnit cu;
	protected MockDWARFCompilationUnit cu2;
	protected DWARFDataTypeManager dwarfDTM;
	protected CategoryPath rootCP;

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._X64, this);
		space = program.getAddressFactory().getDefaultAddressSpace();

		dataMgr = program.getDataTypeManager();
		startTransaction();

		program.getMemory()
				.createInitializedBlock("test", addr(BaseAddress), 500, (byte) 0, TaskMonitor.DUMMY,
					false);

		AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
		DataTypeManagerService dtms = mgr.getDataTypeManagerService();
		builtInDTM = dtms.getBuiltInDataTypesManager();

		importOptions = new DWARFImportOptions();
		dwarfProg =
			new DWARFProgram(program, importOptions, TaskMonitor.DUMMY, new NullSectionProvider());
		rootCP = dwarfProg.getUncategorizedRootDNI().asCategoryPath();

		cu = new MockDWARFCompilationUnit(dwarfProg, 0x1000, 0x2000, 0,
			DWARFCompilationUnit.DWARF_32, (short) 4, 0, (byte) 8, 0,
			DWARFSourceLanguage.DW_LANG_C);
		cu2 = new MockDWARFCompilationUnit(dwarfProg, 0x3000, 0x4000, 0,
			DWARFCompilationUnit.DWARF_32, (short) 4, 0, (byte) 8, 1,
			DWARFSourceLanguage.DW_LANG_C);

		setMockCompilationUnits(cu, cu2);

		DWARFImportSummary importSummary = new DWARFImportSummary();
		dwarfDTM = new DWARFDataTypeManager(dwarfProg, dataMgr, builtInDTM, importSummary);
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		endTransaction();
		dwarfProg.close();
		program.release(this);
	}

	protected void setMockCompilationUnits(DWARFCompilationUnit... compilationUnits) {
		dwarfProg.getCompilationUnits().clear();
		for (DWARFCompilationUnit compilationUnit : compilationUnits) {
			dwarfProg.getCompilationUnits().add(compilationUnit);
		}
	}

	protected void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	protected void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	protected void checkPreconditions() throws CancelledException, DWARFException, IOException {
		dwarfProg.checkPreconditions(monitor);
	}

	protected void importAllDataTypes() throws CancelledException, IOException, DWARFException {
		dwarfProg.checkPreconditions(monitor);
		dwarfDTM.importAllDataTypes(monitor);
	}

	protected void importFunctions() throws CancelledException, IOException, DWARFException {
		dwarfProg.checkPreconditions(monitor);
		dwarfDTM.importAllDataTypes(monitor);

		DWARFImportSummary importSummary = new DWARFImportSummary();
		DWARFFunctionImporter dfi =
			new DWARFFunctionImporter(dwarfProg, dwarfDTM, importOptions, importSummary, monitor);
		dfi.importFunctions();
	}

	protected DIEAggregate getAggregate(DebugInfoEntry die)
			throws CancelledException, IOException, DWARFException {
		dwarfProg.setCurrentCompilationUnit(die.getCompilationUnit(), monitor);
		return dwarfProg.getAggregate(die);
	}

	protected DebugInfoEntry addBaseType(String name, int size, int encoding,
			MockDWARFCompilationUnit dcu) {
		DIECreator tmp = new DIECreator(DW_TAG_base_type)
				.addInt(DW_AT_byte_size, size)
				.addInt(DW_AT_encoding, encoding);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		return tmp.create(dcu);
	}

	protected DebugInfoEntry addInt(MockDWARFCompilationUnit dcu) {
		return addBaseType("int", 4, DW_ATE_signed, dcu);
	}

	protected DebugInfoEntry addFloat(MockDWARFCompilationUnit dcu) {
		return addBaseType("float", 4, DW_ATE_float, dcu);
	}

	protected DebugInfoEntry addDouble(MockDWARFCompilationUnit dcu) {
		return addBaseType("double", 8, DW_ATE_float, dcu);
	}

	protected DebugInfoEntry addTypedef(String name, DebugInfoEntry die,
			MockDWARFCompilationUnit dcu) {
		assertTrue(die.getCompilationUnit() == dcu);
		return new DIECreator(DW_TAG_typedef)
				.addString(DW_AT_name, name)
				.addRef(DW_AT_type, die)
				.create(dcu);
	}

	protected DebugInfoEntry addSubprogram(String name, DebugInfoEntry returnTypeDIE,
			MockDWARFCompilationUnit dcu) {
		assertTrue(returnTypeDIE == null || returnTypeDIE.getCompilationUnit() == dcu);
		DIECreator tmp = new DIECreator(DW_TAG_subprogram);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		if (returnTypeDIE != null) {
			tmp.addRef(DW_AT_type, returnTypeDIE);
		}
		return tmp.create(dcu);
	}

	protected DebugInfoEntry addSubroutineType(String name, DebugInfoEntry returnTypeDIE,
			MockDWARFCompilationUnit dcu) {
		assertTrue(returnTypeDIE == null || returnTypeDIE.getCompilationUnit() == dcu);
		DIECreator tmp = new DIECreator(DW_TAG_subroutine_type);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		if (returnTypeDIE != null) {
			tmp.addRef(DW_AT_type, returnTypeDIE);
		}
		return tmp.create(dcu);
	}

	protected DebugInfoEntry addParam(DebugInfoEntry parent, String name, DebugInfoEntry typeDIE,
			MockDWARFCompilationUnit dcu) {
		assertTrue(typeDIE == null || typeDIE.getCompilationUnit() == dcu);
		assertTrue(parent.getCompilationUnit() == dcu);
		return new DIECreator(DW_TAG_formal_parameter)
				.addRef(DW_AT_type, typeDIE)
				.setParent(parent)
				.create(dcu);
	}

	protected DIECreator newSpecStruct(DebugInfoEntry declDIE, int size) {
		DIECreator struct = new DIECreator(DW_TAG_structure_type)
				.addRef(DW_AT_specification, declDIE)
				.addInt(DW_AT_byte_size, size);
		return struct;
	}

	protected DIECreator newDeclStruct(String name) {
		DIECreator struct = new DIECreator(DW_TAG_structure_type)
				.addBoolean(DW_AT_declaration, true)
				.addString(DW_AT_name, name);
		return struct;
	}

	protected DIECreator newStruct(String name, int size) {
		DIECreator struct = new DIECreator(DW_TAG_structure_type);
		if (name != null) {
			struct.addString(DW_AT_name, name);
		}
		struct.addInt(DW_AT_byte_size, size);
		return struct;
	}

	protected DebugInfoEntry createEnum(String name, int size, MockDWARFCompilationUnit dcu) {
		DIECreator resultEnum = new DIECreator(DW_TAG_enumeration_type);
		if (name != null) {
			resultEnum.addString(DW_AT_name, name);
		}
		resultEnum.addInt(DW_AT_byte_size, size);
		return resultEnum.create(dcu);
	}

	protected DebugInfoEntry addEnumValue(DebugInfoEntry parentEnum, String valueName,
			long valueValue, MockDWARFCompilationUnit dcu) {
		assertTrue(parentEnum.getCompilationUnit() == dcu);
		DIECreator enumValue = new DIECreator(DW_TAG_enumerator)
				.addString(DW_AT_name, valueName)
				.addInt(DW_AT_const_value, valueValue)
				.setParent(parentEnum);
		return enumValue.create(dcu);
	}

	protected DebugInfoEntry addPtr(DebugInfoEntry targetDIE, MockDWARFCompilationUnit dcu) {
		assertTrue(targetDIE.getCompilationUnit() == dcu);
		return new DIECreator(DW_TAG_pointer_type).addRef(DW_AT_type, targetDIE).create(dcu);
	}

	protected DebugInfoEntry addFwdPtr(MockDWARFCompilationUnit dcu, int fwdRecordOffset) {
		return new DIECreator(DW_TAG_pointer_type)
				.addRef(DW_AT_type, getForwardOffset(dcu, fwdRecordOffset))
				.create(dcu);
	}

	protected long getForwardOffset(MockDWARFCompilationUnit dcu, int count) {
		return dcu.getStartOffset() + dcu.getMockEntryCount() + count;
	}

	protected DIECreator newMember(DebugInfoEntry parentStruct, String fieldName,
			DebugInfoEntry dataType, int offset) {
		assertTrue(
			dataType == null || dataType.getCompilationUnit() == parentStruct.getCompilationUnit());
		return newMember(parentStruct, fieldName, dataType.getOffset(), offset);
	}

	protected DIECreator newMember(DebugInfoEntry parentStruct, String fieldName,
			long memberDIEOffset, int offset) {
		DIECreator field = new DIECreator(DWARFTag.DW_TAG_member)
				.addString(DW_AT_name, fieldName)
				.addRef(DW_AT_type, memberDIEOffset)
				.setParent(parentStruct);
		if (offset != -1) {
			field.addInt(DW_AT_data_member_location, offset);
		}
		return field;
	}

	protected DIECreator newInherit(DebugInfoEntry parentStruct, DebugInfoEntry dataType,
			int offset) {
		assertTrue(
			dataType == null || dataType.getCompilationUnit() == parentStruct.getCompilationUnit());
		DIECreator field = new DIECreator(DW_TAG_inheritance)
				.addRef(DW_AT_type, dataType)
				.addInt(DW_AT_data_member_location, offset)
				.setParent(parentStruct);
		return field;
	}

	protected DebugInfoEntry newArray(MockDWARFCompilationUnit dcu, DebugInfoEntry baseTypeDIE,
			boolean elideEmptyDimRangeValue, int... dimensions) {
		DebugInfoEntry arrayType = new DIECreator(DW_TAG_array_type)
				.addRef(DW_AT_type, baseTypeDIE)
				.create(dcu);
		for (int dimIndex = 0; dimIndex < dimensions.length; dimIndex++) {
			int dim = dimensions[dimIndex];
			DIECreator dimDIE = new DIECreator(DW_TAG_subrange_type).setParent(arrayType);
			if (dim != -1 || !elideEmptyDimRangeValue) {
				dimDIE.addInt(DW_AT_upper_bound, dimensions[dimIndex]);
			}
			dimDIE.create(dcu);
		}
		return arrayType;
	}

	protected DebugInfoEntry newArrayUsingCount(MockDWARFCompilationUnit dcu,
			DebugInfoEntry baseTypeDIE, int count) {
		DebugInfoEntry arrayType = new DIECreator(DW_TAG_array_type)
				.addRef(DW_AT_type, baseTypeDIE)
				.create(dcu);
		DIECreator dimDIE = new DIECreator(DW_TAG_subrange_type)
				.setParent(arrayType);
		dimDIE.addInt(DW_AT_count, count);
		dimDIE.create(dcu);
		return arrayType;
	}

	protected DIECreator newSubprogram(String name, DebugInfoEntry returnType, long startAddress,
			long length) {
		return new DIECreator(DW_TAG_subprogram)
				.addString(DW_AT_name, name)
				.addRef(DW_AT_type, returnType)
				.addUInt(DW_AT_low_pc, startAddress)
				.addUInt(DW_AT_high_pc, length);
	}

	protected DIECreator newFormalParam(DebugInfoEntry subprogram, String paramName,
			DebugInfoEntry paramDataType, int... locationExpr) {
		DIECreator param = new DIECreator(DW_TAG_formal_parameter)
				.addString(DW_AT_name, paramName)
				.addRef(DW_AT_type, paramDataType)
				.addBlock(DW_AT_location, locationExpr)
				.setParent(subprogram);
		return param;
	}

	protected Address addr(long l) {
		return space.getAddress(l);
	}

	protected void assertHasFlexArray(Structure struct) {
		DataTypeComponent component = struct.getComponent(struct.getNumComponents() - 1);
		assertNotNull(component);
		assertEquals(0, component.getLength());
		DataType dt = component.getDataType();
		assertTrue(dt instanceof Array);
		Array a = (Array) dt;
		assertEquals(0, a.getNumElements());
	}

	protected void assertMissingFlexArray(Structure struct) {
		DataTypeComponent component = struct.getComponent(struct.getNumComponents() - 1);
		if (component == null) {
			return;
		}
		assertNotEquals(0, component.getLength());
	}
}
