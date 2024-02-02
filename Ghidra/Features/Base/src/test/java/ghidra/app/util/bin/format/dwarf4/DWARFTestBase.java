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
	protected MockDWARFProgram dwarfProg;
	protected MockDWARFCompilationUnit currentCU;
	protected DWARFDataTypeManager dwarfDTM;
	protected CategoryPath uncatCP;
	protected CategoryPath dwarfRootCP;

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
		dwarfProg = new MockDWARFProgram(program, importOptions, TaskMonitor.DUMMY,
			new NullSectionProvider());
		dwarfDTM = dwarfProg.getDwarfDTM();
		dwarfRootCP = dwarfProg.getRootDNI().asCategoryPath();
		uncatCP = dwarfProg.getUncategorizedRootDNI().asCategoryPath();
	}

	@After
	public void tearDown() throws Exception {
		endTransaction();
		dwarfProg.close();
		program.release(this);
	}

	protected void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	protected void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	protected void buildMockDIEIndexes() throws CancelledException, DWARFException {
		dwarfProg.buildMockDIEIndexes();
	}

	protected void importAllDataTypes() throws CancelledException, IOException, DWARFException {
		buildMockDIEIndexes();
		dwarfDTM.importAllDataTypes(monitor);
	}

	protected void importFunctions() throws CancelledException, IOException, DWARFException {
		buildMockDIEIndexes();
		dwarfDTM.importAllDataTypes(monitor);

		DWARFFunctionImporter dfi = new DWARFFunctionImporter(dwarfProg, monitor);
		dfi.importFunctions();
	}

	protected DIEAggregate getAggregate(DebugInfoEntry die) {
		return dwarfProg.getAggregate(die);
	}

	protected void ensureCompUnit() {
		if (dwarfProg.getCurrentCompUnit() == null) {
			dwarfProg.addCompUnit();
		}
	}

	protected MockDWARFCompilationUnit addCompUnit() {
		return dwarfProg.addCompUnit();
	}

	protected MockDWARFCompilationUnit addCompUnit(int cuLang) {
		return dwarfProg.addCompUnit(cuLang);
	}

	protected DebugInfoEntry addBaseType(String name, int size, int encoding) {
		ensureCompUnit();
		DIECreator tmp = new DIECreator(dwarfProg, DW_TAG_base_type) //
				.addInt(DW_AT_byte_size, size)
				.addInt(DW_AT_encoding, encoding);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		return tmp.create();
	}

	protected DebugInfoEntry addInt() {
		ensureCompUnit();
		return addBaseType("int", 4, DW_ATE_signed);
	}

	protected DebugInfoEntry addFloat() {
		ensureCompUnit();
		return addBaseType("float", 4, DW_ATE_float);
	}

	protected DebugInfoEntry addDouble() {
		ensureCompUnit();
		return addBaseType("double", 8, DW_ATE_float);
	}

	protected DebugInfoEntry addTypedef(String name, DebugInfoEntry die) {
		ensureCompUnit();
		return new DIECreator(dwarfProg, DW_TAG_typedef).addString(DW_AT_name, name)
				.addRef(DW_AT_type, die)
				.create();
	}

	protected DebugInfoEntry addSubprogram(String name, DebugInfoEntry returnTypeDIE) {
		ensureCompUnit();
		DIECreator tmp = new DIECreator(dwarfProg, DW_TAG_subprogram);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		if (returnTypeDIE != null) {
			tmp.addRef(DW_AT_type, returnTypeDIE);
		}
		return tmp.create();
	}

	protected DebugInfoEntry addSubroutineType(String name, DebugInfoEntry returnTypeDIE) {
		ensureCompUnit();
		DIECreator tmp = new DIECreator(dwarfProg, DW_TAG_subroutine_type);
		if (name != null) {
			tmp.addString(DW_AT_name, name);
		}
		if (returnTypeDIE != null) {
			tmp.addRef(DW_AT_type, returnTypeDIE);
		}
		return tmp.create();
	}

	protected DebugInfoEntry addParam(DebugInfoEntry parent, String name, DebugInfoEntry typeDIE) {
		ensureCompUnit();
		return new DIECreator(dwarfProg, DW_TAG_formal_parameter) //
				.addRef(DW_AT_type, typeDIE)
				.setParent(parent)
				.create();
	}

	protected DIECreator newSpecStruct(DebugInfoEntry declDIE, int size) {
		ensureCompUnit();
		DIECreator struct = new DIECreator(dwarfProg, DW_TAG_structure_type) //
				.addRef(DW_AT_specification, declDIE)
				.addInt(DW_AT_byte_size, size);
		return struct;
	}

	protected DIECreator newDeclStruct(String name) {
		ensureCompUnit();
		DIECreator struct = new DIECreator(dwarfProg, DW_TAG_structure_type) //
				.addBoolean(DW_AT_declaration, true)
				.addString(DW_AT_name, name);
		return struct;
	}

	protected DIECreator newStruct(String name, int size) {
		ensureCompUnit();
		DIECreator struct = new DIECreator(dwarfProg, DW_TAG_structure_type);
		if (name != null) {
			struct.addString(DW_AT_name, name);
		}
		struct.addInt(DW_AT_byte_size, size);
		return struct;
	}

	protected DebugInfoEntry createEnum(String name, int size) {
		ensureCompUnit();
		DIECreator resultEnum = new DIECreator(dwarfProg, DW_TAG_enumeration_type);
		if (name != null) {
			resultEnum.addString(DW_AT_name, name);
		}
		resultEnum.addInt(DW_AT_byte_size, size);
		return resultEnum.create();
	}

	protected DebugInfoEntry addEnumValue(DebugInfoEntry parentEnum, String valueName,
			long valueValue) {
		ensureCompUnit();
		DIECreator enumValue = new DIECreator(dwarfProg, DW_TAG_enumerator) //
				.addString(DW_AT_name, valueName)
				.addInt(DW_AT_const_value, valueValue)
				.setParent(parentEnum);
		return enumValue.create();
	}

	protected DebugInfoEntry addPtr(DebugInfoEntry targetDIE) {
		ensureCompUnit();
		return new DIECreator(dwarfProg, DW_TAG_pointer_type) //
				.addRef(DW_AT_type, targetDIE)
				.create();
	}

	protected DebugInfoEntry addFwdPtr(int fwdRecordOffset) {
		ensureCompUnit();
		long absOffset =
			dwarfProg.getRelativeDIEOffset(fwdRecordOffset + /* the ptr die we are about to add */ 1);
		return new DIECreator(dwarfProg, DW_TAG_pointer_type)
				.addRef(DW_AT_type, absOffset)
				.create();
	}

	protected DIECreator newMember(DebugInfoEntry parentStruct, String fieldName,
			DebugInfoEntry dataType, int offset) {
		assertTrue(
			dataType == null || dataType.getCompilationUnit() == parentStruct.getCompilationUnit());
		ensureCompUnit();
		return newMember(parentStruct, fieldName, dataType.getOffset(), offset);
	}

	protected DIECreator newMember(DebugInfoEntry parentStruct, String fieldName,
			long typeDIEOffset, int offset) {
		ensureCompUnit();
		DIECreator field = new DIECreator(dwarfProg, DWARFTag.DW_TAG_member) //
				.addString(DW_AT_name, fieldName)
				.addRef(DW_AT_type, typeDIEOffset)
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
		ensureCompUnit();
		DIECreator field = new DIECreator(dwarfProg, DW_TAG_inheritance) //
				.addRef(DW_AT_type, dataType)
				.addInt(DW_AT_data_member_location, offset)
				.setParent(parentStruct);
		return field;
	}

	protected DebugInfoEntry newArray(DebugInfoEntry baseTypeDIE, boolean elideEmptyDimRangeValue,
			int... dimensions) {
		ensureCompUnit();
		DebugInfoEntry arrayType = new DIECreator(dwarfProg, DW_TAG_array_type) //
				.addRef(DW_AT_type, baseTypeDIE)
				.create();
		for (int dimIndex = 0; dimIndex < dimensions.length; dimIndex++) {
			int dim = dimensions[dimIndex];
			DIECreator dimDIE = new DIECreator(dwarfProg, DW_TAG_subrange_type) //
					.setParent(arrayType);
			if (dim != -1 || !elideEmptyDimRangeValue) {
				dimDIE.addInt(DW_AT_upper_bound, dimensions[dimIndex]);
			}
			dimDIE.create();
		}
		return arrayType;
	}

	protected DebugInfoEntry newArrayUsingCount(DebugInfoEntry baseTypeDIE, int count) {
		ensureCompUnit();
		DebugInfoEntry arrayType = new DIECreator(dwarfProg, DW_TAG_array_type) //
				.addRef(DW_AT_type, baseTypeDIE)
				.create();
		new DIECreator(dwarfProg, DW_TAG_subrange_type) //
				.setParent(arrayType)
				.addInt(DW_AT_count, count)
				.create();
		return arrayType;
	}

	protected DIECreator newSubprogram(String name, DebugInfoEntry returnType, long startAddress,
			long length) {
		ensureCompUnit();
		return new DIECreator(dwarfProg, DW_TAG_subprogram) //
				.addString(DW_AT_name, name)
				.addRef(DW_AT_type, returnType)
				.addUInt(DW_AT_low_pc, startAddress)
				.addUInt(DW_AT_high_pc, length);
	}

	protected DIECreator newFormalParam(DebugInfoEntry subprogram, String paramName,
			DebugInfoEntry paramDataType, int... locationExpr) {
		ensureCompUnit();
		DIECreator param = new DIECreator(dwarfProg, DW_TAG_formal_parameter) //
				.addRef(DW_AT_type, paramDataType)
				.setParent(subprogram);
		if (locationExpr.length > 0) {
			param.addBlock(DW_AT_location, locationExpr);
		}
		if (paramName != null) {
			param.addString(DW_AT_name, paramName);
		}
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
