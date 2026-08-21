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
package ghidra.app.plugin.core.analysis.rust.demangler;

import static ghidra.app.util.bin.format.dwarf.DWARFSourceLanguage.*;
import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;

public class RustDWARFFunctionFixupTest extends DWARFTestBase {

	@Test
	public void testRustMethod_SetsRustCC() throws CancelledException, IOException, DWARFException {
		addCompUnit(DW_LANG_Rust);

		DebugInfoEntry intDIE = addInt();
		newSubprogram("foo", intDIE, 0x410, 10).create();

		importFunctions();

		Function fooFunc = program.getListing().getFunctionAt(addr(0x410));
		assertNotNull(fooFunc);

		assertEquals("foo", fooFunc.getName());
		assertEquals(CompilerSpec.CALLING_CONVENTION_rustcall, fooFunc.getCallingConventionName());
	}

}
