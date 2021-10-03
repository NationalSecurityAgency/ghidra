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
package ghidra.app.plugin.core.decompile;

import java.util.Optional;

import org.junit.*;

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitor;

public class DecompilerTest extends AbstractGhidraHeadedIntegrationTest {
	private Program prog;
	private DecompInterface decompiler;
	private long returnBytesOffset = 0x0;

	@Before
	public void setUp() throws Exception {

		ToyProgramBuilder builder = new ToyProgramBuilder("notepad_decompiler", true);
		builder.createMemory("test", "0x0", 2);
		builder.addBytesReturn(returnBytesOffset);
		builder.createFunction("0x0");
		prog = builder.getProgram();

		decompiler = new DecompInterface();
		decompiler.openProgram(prog);
	}

	@After
	public void tearDown() throws Exception {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}

	@Test
	public void testDecompileInterfaceReturnsAFunction() throws Exception {
		Address addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(0x0);
		Function func = prog.getListing().getFunctionAt(addr);
		DecompileResults decompResults = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		String decompilation = decompResults.getDecompiledFunction().getC();
		Assert.assertNotNull(decompilation);
	}

	@Test
	public void testAlignedCommentIndentation() throws Exception {
		int indent = 20;
		DecompileOptions options = new DecompileOptions();
		options.setCommentIndent(indent);
		options.setCommentIndentAlign(true);
		options.setPRECommentIncluded(true);
		decompiler.setOptions(options);

		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();

		// add a comment to the program listing
		Address returnBytesAddr = space.getAddress(returnBytesOffset);
		int transaction = prog.startTransaction("add comment for indentation test");
		String comment = "aligned-comment-indentation-test";
		prog.getListing().getCodeUnitAt(returnBytesAddr).setComment(CodeUnit.PRE_COMMENT, comment);
		prog.endTransaction(transaction, true);

		Address addr = space.getAddress(0x0);
		Function func = prog.getListing().getFunctionAt(addr);
		DecompileResults decompResults = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		String decompilation = decompResults.getDecompiledFunction().getC();
		Assert.assertNotNull(decompilation);

		Optional<String> commentLineCheck = decompilation.lines().filter(line -> line.contains(comment)).findFirst();
		Optional<String> returnLineCheck = decompilation.lines().filter(line -> line.endsWith("return;")).findFirst();
		Assert.assertTrue(commentLineCheck.isPresent());
		Assert.assertTrue(returnLineCheck.isPresent());

		String commentLine = commentLineCheck.get();
		String returnLine = returnLineCheck.get();

		Assert.assertFalse(commentLine.startsWith(" ".repeat(indent)));

		int commentIndentation = commentLine.indexOf(commentLine.stripLeading());
		int returnIndentation = returnLine.indexOf(returnLine.stripLeading());
		Assert.assertEquals(commentIndentation, returnIndentation);
	}

	@Test
	public void testFixedCommentIndentation() throws Exception {
		int indent = 20;
		DecompileOptions options = new DecompileOptions();
		options.setCommentIndent(indent);
		options.setCommentIndentAlign(false);
		options.setPRECommentIncluded(true);
		decompiler.setOptions(options);

		AddressSpace space = prog.getAddressFactory().getDefaultAddressSpace();

		// add a comment to the program listing
		Address returnBytesAddr = space.getAddress(returnBytesOffset);
		int transaction = prog.startTransaction("add comment for indentation test");
		String comment = "fixed-comment-indentation-test";
		prog.getListing().getCodeUnitAt(returnBytesAddr).setComment(CodeUnit.PRE_COMMENT, comment);
		prog.endTransaction(transaction, true);

		Address addr = space.getAddress(0x0);
		Function func = prog.getListing().getFunctionAt(addr);
		DecompileResults decompResults = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		String decompilation = decompResults.getDecompiledFunction().getC();
		Assert.assertNotNull(decompilation);

		Optional<String> commentLine = decompilation.lines().filter(line -> line.contains(comment)).findFirst();
		Assert.assertTrue(commentLine.isPresent());
		Assert.assertTrue(commentLine.get().startsWith(" ".repeat(indent)));
	}
}
