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

import org.junit.Test;

import ghidra.app.decompiler.component.ClangTextField;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Navigation from the decompiler on a word-addressed language, where a global's address is a
 * constant in words, not bytes.
 */
public class DecompilerWordAddressedNavigationTest extends AbstractDecompilerTest {

	private static final String FILL = "0x0";
	private static final String CLEAR = "0x10";
	private static final long BUF = 0x100; // word offset

	@Override
	protected Program getProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("toy", ProgramBuilder._TOY_WORDSIZE2_BE, this);
		builder.createMemory("ram", FILL, 0x400); // bytes; word 0x100 is inside
		Program p = builder.getProgram();

		int tx = p.startTransaction("assemble");
		try {
			Assembler asm = Assemblers.getAssembler(p);
			// fill:  r12 = &buf; r0 = buf; clear(r12)
			asm.assemble(builder.addr(FILL), "imm r12,#0x100", "load r0,[r12]",
				"call 0x00000010", "ret");
			// clear: *r12 = 0
			asm.assemble(builder.addr(CLEAR), "imm r0,#0x0", "store [r12],r0", "ret");
		}
		finally {
			p.endTransaction(tx, true);
		}
		builder.createFunction(FILL);
		builder.createFunction(CLEAR);
		return p;
	}

	@Test
	public void testDoubleClickOnGlobalAddress_UsesWordOffset() throws Exception {

		// give clear() a pointer parameter so fill() decompiles to clear(&UNK_00000100). No
		// program symbol exists there, so the decompiler names the location itself.
		modifyProgram(p -> {
			Function fill = p.getFunctionManager().getFunctionAt(addr(FILL));
			fill.setName("fill", SourceType.USER_DEFINED);
			Function clear = p.getFunctionManager().getFunctionAt(addr(CLEAR));
			clear.setName("clear", SourceType.USER_DEFINED);
			clear.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			clear.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED,
				new ParameterImpl("p", new PointerDataType(IntegerDataType.dataType), p));
		});

		decompile(FILL);

		// the decompiler names the location (DAT_ or UNK_ prefix, depending on its type)
		ClangTextField line = getLineContaining("&");
		assertNotNull("fill() did not decompile to a call taking &..._00000100:\n" +
			getDecompiledText(), line);
		int lineNumber = line.getLineNumber();
		int column = line.getText().indexOf("_00000100") + 1;
		setDecompilerLocation(lineNumber, column);
		assertTrue(getCursorToken().getText().endsWith("_00000100"));

		doubleClick();

		// The constant is a pointer value, in words. Treating it as a byte offset put the
		// Listing at word 0x80 instead.
		assertListingAddress(wordAddr(BUF));
	}

	@Test
	public void testSpacebaseReference_WordAddressedSpace() {

		AddressFactory addrFactory = program.getAddressFactory();
		AddressSpace space = addrFactory.getDefaultAddressSpace();
		assertEquals(2, space.getAddressableUnitSize());
		AddressSpace constants = addrFactory.getConstantSpace();
		Varnode spacebase = new Varnode(constants.getAddress(0), 4);
		Varnode offset = new Varnode(constants.getAddress(BUF), 4);
		PcodeOp ptrsub = new PcodeOp(addr(FILL), 0, PcodeOp.PTRSUB,
			new Varnode[] { spacebase, offset });

		Address addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(addrFactory,
			program.getLanguage(), ptrsub);

		assertEquals(wordAddr(BUF), addr);
	}

	private Address wordAddr(long wordOffset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(wordOffset, true);
	}

}
