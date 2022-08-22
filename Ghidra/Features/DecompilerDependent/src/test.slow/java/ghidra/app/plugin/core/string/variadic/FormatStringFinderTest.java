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
package ghidra.app.plugin.core.string.variadic;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;

import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.Msg;

public class FormatStringFinderTest extends AbstractProgramBasedTest {

	private static final int BASE_ADDRESS = 0x10000;
	private static final int LENGTH = 0x1000;

	private static final String SIMPLE_FORMAT_STRING = "length: %d";
	private static final byte[] SIMPLE_FORMAT_BYTES =
		SIMPLE_FORMAT_STRING.getBytes(StandardCharsets.US_ASCII);

	private static final int SIMPLE_NON_FORMAT_START = 0x10010;
	private static final String SIMPLE_NON_FORMAT_STRING = "hello";
	private static final byte[] SIMPLE_NON_FORMAT_BYTES =
		SIMPLE_NON_FORMAT_STRING.getBytes(StandardCharsets.US_ASCII);

	private static final int WIDE_CHAR_STRING_START = 0x10020;
	private static final String WCHAR_EXAMPLE = "%s";
	private boolean wcharEncoded = false;

	private static final int SHORT_FORMAT_STRING_START = 0x10030;
	private static final int SHORT_NEAR_END_START = BASE_ADDRESS + LENGTH - 4;
	private static final String SHORT_FORMAT_STRING = "%d";
	private static final byte[] SHORT_FORMAT_STRING_BYTES =
		SHORT_FORMAT_STRING.getBytes(StandardCharsets.US_ASCII);

	private static final int ANSI_COLOR_CODE_START = 0x10040;
	private static final String ANSI_COLOR_CODE_STRING = "reproduces error : %s!\n\u001b[0m";
	private static final byte[] ANSI_COLOR_CODE_BYTES =
		ANSI_COLOR_CODE_STRING.getBytes(StandardCharsets.US_ASCII);

	@Test
	public void testNullTerminatedStringFinder() throws Exception {
		initialize();
		PcodeFunctionParser parser = new PcodeFunctionParser(program);
		AddressFactory addrFactory = program.getAddressFactory();

		Pointer charPointer = program.getDataTypeManager().getPointer(new CharDataType());
		Pointer widePointer = program.getDataTypeManager()
				.getPointer(new WideCharDataType(program.getDataTypeManager()));

		Address base = addrFactory.getConstantAddress(BASE_ADDRESS);
		String simpleFormat = parser.findNullTerminatedString(base, charPointer);
		assertEquals(SIMPLE_FORMAT_STRING, simpleFormat);

		Address simpleNonFormatAddr = addrFactory.getConstantAddress(SIMPLE_NON_FORMAT_START);
		String simpleNonFormat = parser.findNullTerminatedString(simpleNonFormatAddr, charPointer);
		assertEquals(SIMPLE_NON_FORMAT_STRING, simpleNonFormat);

		if (wcharEncoded) {
			Address wideCharStringAddr = addrFactory.getConstantAddress(WIDE_CHAR_STRING_START);
			String wide = parser.findNullTerminatedString(wideCharStringAddr, widePointer);
			assertEquals(WCHAR_EXAMPLE, wide);
		}

		Address shortAddr = addrFactory.getConstantAddress(SHORT_FORMAT_STRING_START);
		String shortString = parser.findNullTerminatedString(shortAddr, charPointer);
		assertEquals(SHORT_FORMAT_STRING, shortString);

		Address shortNearEndAddr = addrFactory.getConstantAddress(SHORT_NEAR_END_START);
		shortString = parser.findNullTerminatedString(shortNearEndAddr, charPointer);
		assertEquals(SHORT_FORMAT_STRING, shortString);

		Address ansiColorAddr = addrFactory.getConstantAddress(ANSI_COLOR_CODE_START);
		String ansiColorString = parser.findNullTerminatedString(ansiColorAddr, charPointer);
		assertEquals(ANSI_COLOR_CODE_STRING, ansiColorString);

	}

	@Override
	protected Program getProgram() {
		ProgramBuilder builder = null;
		try {
			builder = new ProgramBuilder("test", ProgramBuilder._X64, "gcc", null);
			builder.createMemory("test", Integer.toHexString(BASE_ADDRESS), LENGTH, "test",
				(byte) 0x0);
			builder.setBytes(Integer.toHexString(BASE_ADDRESS), SIMPLE_FORMAT_BYTES);
			builder.setBytes(Integer.toHexString(SIMPLE_NON_FORMAT_START), SIMPLE_NON_FORMAT_BYTES);
			try {
				builder.setBytes(Integer.toHexString(WIDE_CHAR_STRING_START),
					WCHAR_EXAMPLE.getBytes("UTF-32LE"));
				wcharEncoded = true;
			}
			catch (UnsupportedEncodingException e) {
				Msg.warn(this, e.getMessage());
			}
			builder.setBytes(Integer.toHexString(SHORT_FORMAT_STRING_START),
				SHORT_FORMAT_STRING_BYTES);
			builder.setBytes(Integer.toHexString(SHORT_NEAR_END_START), SHORT_FORMAT_STRING_BYTES);
			builder.setBytes(Integer.toHexString(ANSI_COLOR_CODE_START), ANSI_COLOR_CODE_BYTES);
		}
		catch (Exception e) {
			fail("Exception creating testing program: " + e.getMessage());
		}

		return builder.getProgram();
	}

}
