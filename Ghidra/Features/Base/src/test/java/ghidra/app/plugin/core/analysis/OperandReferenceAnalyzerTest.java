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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class OperandReferenceAnalyzerTest extends AbstractGenericTest {

	private ProgramDB program;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("OperandReferenceAnalyzerTest", ProgramBuilder._X64);
		builder.createMemory(".mem", "0x101000", 0x1000);
		program = builder.getProgram();
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testPointerCreatedWhenTargetIsUndefinedData() throws Exception {
		assertPointerCreatedWhenReferenceTargets(new Undefined1DataType(), "undefined data");
	}

	@Test
	public void testPointerCreatedWhenTargetIsUndefinedArray() throws Exception {
		assertPointerCreatedWhenReferenceTargets(
				new ArrayDataType(new Undefined1DataType(), 16, 1), "undefined array");
	}

	private void assertPointerCreatedWhenReferenceTargets(DataType targetDataType,
			String description) throws Exception {
		Address target = builder.addr("0x101100");
		Address reader = builder.addr("0x101080");

		builder.putAddress("0x101100", "0x101200");
		builder.withTransaction(() -> {
			new CreateDataCmd(target, targetDataType).applyTo(program);
			program.getReferenceManager()
					.addMemoryReference(reader, target, RefType.READ, SourceType.USER_DEFINED, 0);
		});

		runAnalyzer(reader);

		Data data = program.getListing().getDefinedDataAt(target);
		assertNotNull(data);
		assertTrue("expected a pointer at the " + description + ", got " + data.getDataType().getName(),
				data.isPointer());
	}

	private void runAnalyzer(Address inSet) throws CancelledException {
		int tx = program.startTransaction("analyze");
		try {
			new OperandReferenceAnalyzer().added(program, new AddressSet(inSet, inSet),
					TaskMonitor.DUMMY, new MessageLog());
		} finally {
			program.endTransaction(tx, true);
		}
	}
}
