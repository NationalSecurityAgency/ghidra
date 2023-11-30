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
package sarif;

import static org.junit.Assert.assertNotNull;

import java.io.StringWriter;

import org.junit.After;
import org.junit.Before;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramDiff;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.DummyCancellableTaskMonitor;
import sarif.managers.ProgramSarifMgr;

public class AbstractSarifTest extends AbstractGhidraHeadedIntegrationTest {

	protected ProgramBuilder builder;
	protected Program program, program2;
	protected int txIdOut;
	protected int txIdIn;

	protected Address entry;
	protected MemoryBlock block;
	protected DummyCancellableTaskMonitor monitor;
	protected ProgramSarifMgr mgr;
	protected AddressSet addrSet;

	protected byte[] asm = { (byte) 0x55, // PUSH EBP
			(byte) 0x8b, (byte) 0xec, // MOV EBP, ESP
			(byte) 0x81, (byte) 0xec, (byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, // SUB ESP, 0x200
			(byte) 0x6a, (byte) 0x00, // PUSH 0x0
			(byte) 0x68, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, // PUSH 0x100
			(byte) 0xeb, (byte) 0xee, // JUMP <-
			(byte) 0xcc, (byte) 0xcc, (byte) 0xcc, (byte) 0xcc, (byte) 0xcc, (byte) 0xcc, // HACK: buffer requires 2 x
			(byte) 0x80 // proto length
	};

	protected int[] instOffsets = { 0, 1, 3, 9, 11, 16, 17 };

	public AbstractSarifTest() {
		super();
	}

	public ProgramDiff readWriteCompare() throws Exception {
		SarifProgramOptions options = new SarifProgramOptions();
		mgr.write(program, addrSet, monitor, options);
		StringWriter w = (StringWriter) mgr.getBaseWriter();
		StringBuffer result = w.getBuffer();

		reset();
		mgr.setFileContents(result.toString());
		mgr.read(program2, monitor);

		ProgramDiff programDiff = new ProgramDiff(program, program2);
		AddressSet addressesOnlyInOne = programDiff.getAddressesOnlyInOne();
		AddressSet addressesOnlyInTwo = programDiff.getAddressesOnlyInTwo();
		assert (addressesOnlyInOne.isEmpty());
		assert (addressesOnlyInTwo.isEmpty());
		return programDiff;
	}

	@Before
	public void setUp() throws Exception {
		program = getProgram("TestOutProgram");
		program.addConsumer(this);

		txIdOut = program.startTransaction("TestOut");

		if (program.getMemory().isEmpty()) {
			AddressFactory af = program.getAddressFactory();
			entry = af.getAddress("01002000");
			block = program.getMemory().createInitializedBlock("EMPTY", entry, 0x4000, (byte) 0, null, false);
			assertNotNull(block);
		}

		addrSet = new AddressSet(program.getMemory());

		monitor = new DummyCancellableTaskMonitor();
		mgr = new ProgramSarifMgr(program);
		mgr.useTempFileForBytes(getTestDirectoryPath());
	}

	protected Program getProgram(String progName) throws Exception {
		builder = new ProgramBuilder(progName, ProgramBuilder._X86);
		return builder.getProgram();
	}

	public void reset() throws Exception {
		if (program != null) {
			if (txIdOut != -1) {
				program.endTransaction(txIdOut, true);
			}
			txIdOut = -1;
		}

		builder = new ProgramBuilder("TestInProgram", ProgramBuilder._X86);
		program2 = builder.getProgram();
		program2.addConsumer(this);

		txIdIn = program2.startTransaction("TestIn");
	}

	@After
	public void tearDown() throws Exception {
		if (program2 != null) {
			if (txIdIn != -1) {
				program2.endTransaction(txIdIn, true);
			}
			program2.release(this);
		}
		if (program != null) {
			if (txIdOut != -1) {
				program.endTransaction(txIdOut, true);
			}
			program.release(this);
		}
	}

	protected Address addr(long l) {
		return entry.add(l);
	}
}
