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

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.Test;

import ghidra.app.decompiler.component.ClangTextField;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Navigation from the decompiler on a language with several data spaces whose default data space
 * is the code space, so the space of a global's address can only come from the decompiler.
 */
public class DecompilerMultipleDataSpaceNavigationTest extends AbstractDecompilerTest {

	private static final String FILL = "CODE:0000";
	private static final String CLEAR = "CODE:0010";
	private static final String BUF = "EXTMEM:0100";
	private static final long BUF_OFFSET = 0x100;

	@Override
	protected Program getProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("8051", ProgramBuilder._8051, this);
		builder.createMemory("CODE", FILL, 0x400);
		builder.createMemory("INTMEM", "INTMEM:20", 0xe0);
		builder.createMemory("EXTMEM", "EXTMEM:0000", 0x1000);

		// fill: mov DPTR,#0x100; movx A,@DPTR; lcall clear; ret        clear: ret
		builder.setBytes(FILL, "90 01 00 e0 12 00 10 22", true);
		builder.setBytes(CLEAR, "22", true);
		builder.createFunction(FILL);
		builder.createFunction(CLEAR);
		return builder.getProgram();
	}

	@Test
	public void testDoubleClickOnGlobalAddress_UsesSpaceOfGlobal() throws Exception {

		// clear() takes a pointer into EXTMEM, so fill() decompiles to clear(&UNK_EXTMEM_0100).
		// No program symbol exists there, so the decompiler names the location itself.
		modifyProgram(p -> {
			Function fill = p.getFunctionManager().getFunctionAt(addr(FILL));
			fill.setName("fill", SourceType.USER_DEFINED);
			Function clear = p.getFunctionManager().getFunctionAt(addr(CLEAR));
			clear.setName("clear", SourceType.USER_DEFINED);
			clear.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			AddressSpace extmem = p.getAddressFactory().getAddressSpace("EXTMEM");
			DataType extmemPointer = new PointerTypedef(null, ByteDataType.dataType, 2,
				p.getDataTypeManager(), extmem);
			clear.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED, new ParameterImpl("p", extmemPointer, p));
		});

		decompile(FILL);

		ClangTextField line = getLineContaining("_EXTMEM_0100");
		assertNotNull("fill() did not decompile to a call taking &..._EXTMEM_0100:\n" +
			getDecompiledText(), line);
		int lineNumber = line.getLineNumber();
		int column = line.getText().indexOf("_EXTMEM_0100") + 1;
		setDecompilerLocation(lineNumber, column);
		assertTrue(getCursorToken().getText().endsWith("_EXTMEM_0100"));

		doubleClick();

		// The language's default data space is CODE, so only the space the decompiler attached
		// to the reference can put the Listing in EXTMEM
		Address buf = program.getAddressFactory().getAddress(BUF);
		assertNotNull(buf);
		assertListingAddress(buf);
	}

	@Test
	public void testSpacebaseReference_UsesSpaceOfGlobal() throws Exception {

		modifyProgram(p -> {
			Function clear = p.getFunctionManager().getFunctionAt(addr(CLEAR));
			clear.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			AddressSpace extmem = p.getAddressFactory().getAddressSpace("EXTMEM");
			DataType extmemPointer = new PointerTypedef(null, ByteDataType.dataType, 2,
				p.getDataTypeManager(), extmem);
			clear.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED, new ParameterImpl("p", extmemPointer, p));
		});

		decompile(FILL);

		// the argument to clear() is PTRSUB(<spacebase>, #0x100), with the spacebase typed as a
		// pointer into EXTMEM by the decompiler
		PcodeOp ptrsub = findSpacebaseReference(BUF_OFFSET);
		assertNotNull("No PTRSUB with offset 0x100 in\n" + getDecompiledText(), ptrsub);
		AddressFactory addrFactory = program.getAddressFactory();
		Address expected = addrFactory.getAddress(BUF);

		// with and without a language: the typed space wins over any default
		assertEquals(expected, HighFunctionDBUtil.getSpacebaseReferenceAddress(addrFactory,
			program.getLanguage(), ptrsub));
		assertEquals(expected, HighFunctionDBUtil.getSpacebaseReferenceAddress(addrFactory,
			null, ptrsub));
	}

	private PcodeOp findSpacebaseReference(long offset) {
		Iterator<PcodeOpAST> ops = getHighFunction().getPcodeOps();
		while (ops.hasNext()) {
			PcodeOp op = ops.next();
			if (op.getOpcode() != PcodeOp.PTRSUB) {
				continue;
			}
			Varnode base = op.getInput(0);
			Varnode off = op.getInput(1);
			if (base.isConstant() && off.isConstant() && off.getOffset() == offset) {
				return op;
			}
		}
		return null;
	}
}
