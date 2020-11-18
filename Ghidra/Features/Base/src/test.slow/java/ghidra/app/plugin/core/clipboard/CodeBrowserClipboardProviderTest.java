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
package ghidra.app.plugin.core.clipboard;

import static org.hamcrest.core.IsInstanceOf.*;
import static org.junit.Assert.*;

import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;

import org.junit.Before;
import org.junit.Test;

import docking.dnd.StringTransferable;
import docking.widgets.OptionDialog;
import ghidra.app.util.ByteCopier;
import ghidra.app.util.ByteCopier.ProgrammingByteStringTransferable;
import ghidra.app.util.ClipboardType;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.DummyTool;
import ghidra.util.NumericUtilities;
import ghidra.util.exception.AssertException;
import ghidra.util.task.TaskMonitor;

public class CodeBrowserClipboardProviderTest extends AbstractGhidraHeadedIntegrationTest {

	private Program program;
	private CodeBrowserClipboardProvider clipboardProvider;

	@Before
	public void setUp() throws Exception {

		program = createProgram();
		PluginTool tool = new DummyTool() {
			@Override
			public boolean execute(Command command, DomainObject obj) {
				boolean result = command.applyTo(obj);
				if (!result) {
					throw new AssertException("Failed to write bytes");
				}
				return true;
			}
		};

		clipboardProvider = new CodeBrowserClipboardProvider(tool, null);
		clipboardProvider.setProgram(program);
	}

	private Program createProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("default", ProgramBuilder._TOY, this);

		builder.createMemory("test", "0x01001050", 20000);

		builder.setBytes("0x01001050",
			"0e 5e f4 77 33 58 f4 77 91 45 f4 77 88 7c f4 77 8d 70 f5 77 05 62 f4 77 f0 a3 " +
				"f4 77 09 56 f4 77 10 17 f4 77 f7 29 f6 77 02 59 f4 77");

		builder.setBytes("0x01002050", "00 00 00 00 00 00 00 00 00 00 00 00 00");

		builder.createMemoryReference("0x01002cc0", "0x01002cf0", RefType.DATA,
			SourceType.USER_DEFINED);
		builder.createMemoryReference("0x01002d04", "0x01002d0f", RefType.DATA,
			SourceType.USER_DEFINED);

		DataType dt = DataType.DEFAULT;
		Parameter p = new ParameterImpl(null, dt, builder.getProgram());
		builder.createEmptyFunction("ghidra", "0x01002cf5", 1, dt, p);
		builder.createEmptyFunction("sscanf", "0x0100415a", 1, dt, p);

		builder.setBytes("0x0100418c", "ff 15 08 10 00 01");
		builder.disassemble("0x0100418c", 6);

		return builder.getProgram();
	}

	@Test
	public void testCopyPasteSpecial_PythonByteString() throws Exception {

		int length = 4;
		clipboardProvider.setSelection(selection("0x01001050", length));
		ClipboardType type = ByteCopier.PYTHON_BYTE_STRING_TYPE;
		Transferable transferable = clipboardProvider.copySpecial(type, TaskMonitor.DUMMY);
		assertThat(transferable, instanceOf(ProgrammingByteStringTransferable.class));

		String byteString = (String) transferable.getTransferData(DataFlavor.stringFlavor);
		assertEquals("b'\\x0e\\x5e\\xf4\\x77'", byteString);

		String pasteAddress = "0x01002050";
		paste(pasteAddress, transferable);
		assertBytesAt(pasteAddress, "0e 5e f4 77", length);
	}

	@Test
	public void testCopyPasteSpecial_PythonListString() throws Exception {

		int length = 4;
		clipboardProvider.setSelection(selection("0x01001050", 4));
		ClipboardType type = ByteCopier.PYTHON_LIST_TYPE;
		Transferable transferable = clipboardProvider.copySpecial(type, TaskMonitor.DUMMY);
		assertThat(transferable, instanceOf(ProgrammingByteStringTransferable.class));

		String byteString = (String) transferable.getTransferData(DataFlavor.stringFlavor);
		assertEquals("[ 0x0e, 0x5e, 0xf4, 0x77 ]", byteString);

		String pasteAddress = "0x01002050";
		paste(pasteAddress, transferable);
		assertBytesAt(pasteAddress, "0e 5e f4 77", length);
	}

	@Test
	public void testCopyPasteSpecial_CppByteArray() throws Exception {

		int length = 4;
		clipboardProvider.setSelection(selection("0x01001050", 4));
		ClipboardType type = ByteCopier.CPP_BYTE_ARRAY_TYPE;
		Transferable transferable = clipboardProvider.copySpecial(type, TaskMonitor.DUMMY);
		assertThat(transferable, instanceOf(ProgrammingByteStringTransferable.class));

		String byteString = (String) transferable.getTransferData(DataFlavor.stringFlavor);
		assertEquals("{ 0x0e, 0x5e, 0xf4, 0x77 }", byteString);

		String pasteAddress = "0x01002050";
		paste(pasteAddress, transferable);
		assertBytesAt(pasteAddress, "0e 5e f4 77", length);
	}

	@Test
	public void testCopyPaste_ByteString() throws Exception {

		String byteString = "0e 5e f4 77";
		StringTransferable transferable = new StringTransferable(byteString);

		String pasteAddress = "0x01002050";
		paste(pasteAddress, transferable);
		assertBytesAt(pasteAddress, byteString, 4);
	}

	@Test
	public void testCopyPaste_ByteString_MixedWithNonAscii() throws Exception {

		// the byte string contains ascii and non-ascii
		String byteString =
			"0e " + ((char) 0x80) + " 5e " + ((char) 0x81 + " f4 " + ((char) 0x82)) + " 77";
		String asciiByteString = "0e 5e f4 77";
		StringTransferable transferable = new StringTransferable(byteString);

		String pasteAddress = "0x01002050";
		paste(pasteAddress, transferable);
		assertBytesAt(pasteAddress, asciiByteString, 4);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void paste(String address, Transferable transferable) {

		tx(program, () -> {
			doPaste(address, transferable);
		});
	}

	private void doPaste(String address, Transferable transferable) {
		clipboardProvider.setLocation(location(address));
		runSwing(() -> clipboardProvider.paste(transferable), false);

		OptionDialog confirmDialog = waitForDialogComponent(OptionDialog.class);
		pressButtonByText(confirmDialog, "Yes");

		waitForTasks();
		program.flushEvents();
		waitForSwing();
	}

	private void assertBytesAt(String address, String bytes, int length)
			throws MemoryAccessException {
		Memory memory = program.getMemory();
		byte[] memoryBytes = new byte[length];
		memory.getBytes(addr(address), memoryBytes, 0, length);

		String memoryByteString = NumericUtilities.convertBytesToString(memoryBytes, " ");
		assertEquals(bytes, memoryByteString);
	}

	private ProgramSelection selection(String addressString, int n) {
		Address address = addr(addressString);
		AddressSetView addresses = new AddressSet(address, address.add(n - 1));
		return new ProgramSelection(addresses);
	}

	private Address addr(String addr) {
		return program.getAddressFactory().getAddress(addr);
	}

	private ProgramLocation location(String addressString) {
		return new ProgramLocation(program, addr(addressString));
	}
}
