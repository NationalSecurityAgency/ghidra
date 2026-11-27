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

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FindNoReturnFunctionsAnalyzerTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private ExternalLocation malloc;

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("FindNoReturnFunctionsAnalyzerTest", ProgramBuilder._X64);
		builder.createMemory(".text", "0x100000", 0x1000);
		program = builder.getProgram();
		malloc = builder.createExternalFunction(null, "libc.so.6", "malloc");
	}

	@After
	public void tearDown() {
		builder.dispose();
	}

	@Test
	public void testReturningExternalIsNotMarkedFromThreeFunctionBoundaryCallSites()
			throws Exception {
		int tx = program.startTransaction("set up call sites");
		try {
			createBoundaryCallSites(malloc);

			// These ordinary callers contain clear fall-through instructions and returns.
			for (int i = 0; i < 10; i++) {
				int address = 0x100100 + i * 0x20;
				putAndDisassemble(address, "48 83 ec 08 ff d0 48 89 c7 48 83 c4 08 c3");
				createFunction(address);
				addCallReference(address + 4);
			}
		}
		finally {
			program.endTransaction(tx, true);
		}

		runAnalyzer();

		assertFalse("ten valid return paths must contradict three heuristic call-site indicators",
			getMallocFunction().hasNoReturn());
	}

	@Test
	public void testThreeSuspiciousSitesStillMarkOpaqueTargetNoReturn() throws Exception {
		ExternalLocation opaque =
			builder.createExternalFunction(null, "opaque.so", "unknown_target");
		int tx = program.startTransaction("set up opaque call sites");
		try {
			createBoundaryCallSites(opaque);
		}
		finally {
			program.endTransaction(tx, true);
		}

		runAnalyzer();

		Function function =
			program.getFunctionManager().getFunctionAt(opaque.getExternalSpaceAddress());
		assertTrue("three suspicious sites with no known return continuation remain sufficient",
			function.hasNoReturn());
	}

	@Test
	public void testReturnInKnownNoReturnCallerDoesNotContradictTarget() throws Exception {
		int tx = program.startTransaction("set up known no-return caller");
		try {
			createBoundaryCallSites(malloc);
			int address = 0x100100;
			putAndDisassemble(address, "48 83 ec 08 ff d0 48 89 c7 48 83 c4 08 c3");
			Function caller = createFunction(address);
			caller.setNoReturn(true);
			addCallReference(address + 4);
		}
		finally {
			program.endTransaction(tx, true);
		}

		runAnalyzer();

		assertTrue("a trailing return in an already non-returning function is not evidence",
			getMallocFunction().hasNoReturn());
	}

	private void createBoundaryCallSites(ExternalLocation target) throws Exception {
		// Each caller aligns the stack before the call. The immediate continuation is
		// also an entry point, modeling shared cleanup tails that restore the stack and
		// return to the wrapper's caller; these labels are not standalone ABI functions.
		for (int i = 0; i < 3; i++) {
			int address = 0x100000 + i * 0x20;
			putAndDisassemble(address, "48 83 ec 08 ff d0 48 83 c4 08 c3");
			createFunction(address);
			createFunction(address + 6);
			addCallReference(address + 4, target);
		}
	}

	private void putAndDisassemble(int address, String bytes) throws Exception {
		String addressString = "0x" + Integer.toHexString(address);
		builder.setBytes(addressString, bytes);
		Address start = builder.addr(addressString);
		Address end = start.add(bytes.split(" ").length - 1);
		DisassembleCommand cmd = new DisassembleCommand(new AddressSet(start, end), null, false);
		assertTrue("failed to disassemble test bytes at " + addressString,
			cmd.applyTo(program, TaskMonitor.DUMMY));
	}

	private Function createFunction(int address) throws Exception {
		return builder.createFunction("0x" + Integer.toHexString(address));
	}

	private void addCallReference(int address) throws Exception {
		addCallReference(address, malloc);
	}

	private void addCallReference(int address, ExternalLocation target) throws Exception {
		ReferenceManager refs = program.getReferenceManager();
		Address call = builder.addr("0x" + Integer.toHexString(address));
		refs.addExternalReference(call, 0, target, SourceType.IMPORTED,
			RefType.UNCONDITIONAL_CALL);
		refs.addExternalReference(call, 1, target, SourceType.IMPORTED, RefType.READ);
	}

	private Function getMallocFunction() {
		return program.getFunctionManager().getFunctionAt(malloc.getExternalSpaceAddress());
	}

	private void runAnalyzer() throws CancelledException {
		int tx = program.startTransaction("run no-return analyzer");
		try {
			new FindNoReturnFunctionsAnalyzer().added(program, program.getMemory(), TaskMonitor.DUMMY,
				new MessageLog());
		}
		finally {
			program.endTransaction(tx, true);
		}
	}
}
