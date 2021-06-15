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

import java.util.ArrayList;
import java.util.List;

import org.junit.*;

import ghidra.app.util.bin.format.pdb.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for the {@link DataTypeConflictHandler conflict handler} stuff.
 *  
 * 
 */
public class ConflictHandlerTest2 extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dtm;
	private int transactionID;

	public ConflictHandlerTest2() {
		super();
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._X64, this);
		dtm = program.getDataTypeManager();
		startTransaction();
	}

	@After
	public void tearDown() throws Exception {
		endTransaction();
		program.release(this);
	}

	@Test
	public void testDataTypeConflicts() {
		DataTypeConflictHandler handler =
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER;

		// First set
		Composite testStruct1 = createComposite(dtm, "outer");
		Pointer pointer1 = new PointerDataType(testStruct1, -1, dtm);

		FunctionDefinitionDataType fn1 =
			new FunctionDefinitionDataType(CategoryPath.ROOT, "fn1", dtm);
		fn1.setReturnType(pointer1);
		fn1.setGenericCallingConvention(GenericCallingConvention.cdecl);
		fn1.setArguments(new ParameterDefinition[0]);

		Composite internalStruct1 = createComposite(dtm, "inner");
		Pointer internalPointer1 = new PointerDataType(internalStruct1, -1, dtm);

		fillComposite(testStruct1, TaskMonitor.DUMMY, internalPointer1);
		fillComposite(internalStruct1, TaskMonitor.DUMMY, null);

		// Second set
		Composite testStruct2 = createComposite(dtm, "outer");
		Pointer pointer2 = new PointerDataType(testStruct2, -1, dtm);

		FunctionDefinitionDataType fn2 =
			new FunctionDefinitionDataType(CategoryPath.ROOT, "fn2", dtm);
		fn2.setReturnType(pointer2);
		fn2.setGenericCallingConvention(GenericCallingConvention.cdecl);
		fn2.setArguments(new ParameterDefinition[0]);

		Composite internalStruct2 = createComposite(dtm, "inner");
		Pointer internalPointer2 = new PointerDataType(internalStruct2, -1, dtm);

		fillComposite(testStruct2, TaskMonitor.DUMMY, internalPointer2);
//		fillComposite(internalStruct2, monitor, null); // Without this line, we get a conflict

		// Resolve
		DataType t1 = dtm.resolve(testStruct1, handler);
		DataType f1 = dtm.resolve(fn1, handler);

		DataType t2 = dtm.resolve(testStruct2, handler);
		DataType f2 = dtm.resolve(fn2, handler);

		System.out.println(t1.toString());
		System.out.println(f1.toString());
		System.out.println(t2.toString());
		System.out.println(f2.toString());
	}

	private static Composite createComposite(DataTypeManager dtm, String name) {
		Composite composite = new StructureDataType(CategoryPath.ROOT, name, 0, dtm);
		return composite;
	}

	private static void fillComposite(Composite composite, TaskMonitor monitor, DataType extra) {
		List<DefaultTestPdbMember> members = new ArrayList<>();
		DefaultTestPdbMember member;
		int size = 8;
		DataType intxy = IntegerDataType.dataType;
		member = new DefaultTestPdbMember("x", intxy, 0);
		members.add(member);
		member = new DefaultTestPdbMember("y", intxy, 4);
		members.add(member);
		if (extra != null) {
			member = new DefaultTestPdbMember("z", extra, 8);
			members.add(member);
			size += extra.getLength();
		}
		try {
			if (!DefaultCompositeMember.applyDataTypeMembers(composite, false, size, members,
				msg -> Msg.warn(ConflictHandlerTest2.class, msg), monitor)) {
				((Structure) composite).deleteAll();
			}
		}
		catch (Exception e) {
			Msg.info(null, "Research exception thrown");
		}
	}

	private static class DefaultTestPdbMember extends PdbMember {

		private DataType dataType;

		/**
		 * Default PDB member construction
		 * @param name member field name.
		 * @param dataType for the field.
		 * @param offset member's byte offset within the root composite.
		 */
		DefaultTestPdbMember(String name, DataType dataType, int offset) {
			super(name, dataType.getName(), offset, null);
			this.dataType = dataType;
		}

		@Override
		public String getDataTypeName() {
			return dataType.getName();
		}

		@Override
		protected WrappedDataType getDataType() throws CancelledException {
			if (dataType instanceof ArrayDataType) {
				int size = 1; // mocking for now
				if (size == 0) {
					return new WrappedDataType(dataType, true, false);
				}
			}
			return new WrappedDataType(dataType, false, false);
		}

	}
}
