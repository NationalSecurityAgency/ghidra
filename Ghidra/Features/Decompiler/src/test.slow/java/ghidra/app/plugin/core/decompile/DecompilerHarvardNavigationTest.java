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
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Navigation from the decompiler on a Harvard architecture, where code and data live in different
 * address spaces and a global's address is a constant relative to the data space.
 */
public class DecompilerHarvardNavigationTest extends AbstractDecompilerTest {

	private static final String FILL = "code:0000";
	private static final String CLEAR = "code:0006";
	private static final String BUF = "mem:0101";

	@Override
	protected Program getProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("avr", "avr8:LE:16:default", this);
		builder.createMemory("code", FILL, 0x400); // large enough that code:0080 exists
		builder.createMemory("sram", "mem:0100", 0x100);

		// fill:  lds r24,0x101; ldi r24,lo8(0x101); ldi r25,hi8(0x101); rcall clear; ret
		// clear: movw X,r25:r24; ldi r18,10; L: st X+,r1; subi r18,1; brne L; ret
		builder.setBytes(FILL, "80 91 01 01 81 e0 91 e0 01 d0 08 95 " +
			"dc 01 2a e0 1d 92 21 50 f1 f7 08 95", true);
		builder.createFunction(FILL);
		builder.createFunction(CLEAR);
		return builder.getProgram();
	}

	@Test
	public void testDoubleClickOnGlobalAddress_NavigatesToDataSpace() throws Exception {

		// give clear() a pointer parameter so fill() decompiles to clear(&DAT_mem_0101). No
		// program symbol exists at mem:0101, so the decompiler names the location itself
		modifyProgram(p -> {
			Function fill = p.getFunctionManager().getFunctionAt(addr(FILL));
			fill.setName("fill", SourceType.USER_DEFINED);
			Function clear = p.getFunctionManager().getFunctionAt(addr(CLEAR));
			clear.setName("clear", SourceType.USER_DEFINED);
			clear.setReturnType(VoidDataType.dataType, SourceType.USER_DEFINED);
			clear.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
				SourceType.USER_DEFINED,
				new ParameterImpl("p", new PointerDataType(ByteDataType.dataType), p));
		});

		decompile(FILL);

		// the decompiler names the location (DAT_ or UNK_ prefix, depending on its type)
		ClangTextField line = getLineContaining("&");
		assertNotNull("fill() did not decompile to a call taking &..._mem_0101:\n" +
			getDecompiledText(), line);
		int lineNumber = line.getLineNumber();
		int column = line.getText().indexOf("_mem_0101") + 1;
		setDecompilerLocation(lineNumber, column);
		assertTrue(getCursorToken().getText().endsWith("_mem_0101"));

		doubleClick();

		// The constant 0x101 is an offset into the data space. Resolving it in the function's code
		// space instead put the Listing at code:0080.1 (the code space is word addressed).
		Address buf = program.getAddressFactory().getAddress(BUF);
		assertNotNull(buf);
		assertListingAddress(buf);
	}

	@Test
	public void testSpacebaseReference_ResolvesInDataSpace() {

		// &global is encoded as PTRSUB(<spacebase>, #offset); the offset is relative to the data
		// space, which on this language is 'mem', not the default 'code' space
		AddressFactory addrFactory = program.getAddressFactory();
		AddressSpace constants = addrFactory.getConstantSpace();
		Varnode spacebase = new Varnode(constants.getAddress(0), 2);
		Varnode offset = new Varnode(constants.getAddress(0x101), 2);
		PcodeOp ptrsub = new PcodeOp(addr(FILL), 0, PcodeOp.PTRSUB,
			new Varnode[] { spacebase, offset });

		Address addr = HighFunctionDBUtil.getSpacebaseReferenceAddress(addrFactory,
			program.getLanguage(), ptrsub);

		assertEquals(program.getAddressFactory().getAddress(BUF), addr);
	}

}
