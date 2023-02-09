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

import org.junit.*;

import ghidra.app.decompiler.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguageVolatilityTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class DecompilerPspecVolatilityTest extends SleighLanguageVolatilityTest {
	private Program prog;
	private DecompInterface decompiler;

	private String functionBytes =
		"84 ff 02 c0 8d 9a 01 c0 8d 98 85 ff 02 c0 a4 9a 01 c0 a4 98 2f " +
			"b7 86 ff 05 c0 f8 94 90 91 02 01 90 68 04 c0 f8 94 90 91 02 01 9f 77 90 93 02 01" +
			" 2f bf 87 ff 02 c0 a3 9a 01 c0 a3 98 8f 9a 85 e0 8a 95 f1 f7 00 00 8f 98 08";

	private int functionLength = 27;
	private String addressString = "0x1000";
	private String decompilation;
	private String decompilerPORTFNotVolatileString = "DAT_mem_0031 = DAT_mem_0031";
	private String decompilerPORTGNotVolatileString = "DAT_mem_0034 = DAT_mem_0034";
	private boolean decompilerPORTFVolatile;
	private boolean decompilerPORTGVolatile;

	public void setUp(Boolean symbolVolatile, Integer symbolSize, Boolean memoryVolatile,
			boolean reverse) throws Exception {
		super.setUp(symbolVolatile, symbolSize, memoryVolatile, reverse);

		ProgramBuilder builder = new ProgramBuilder("test", lang);

		builder.setBytes(addressString, functionBytes);
		builder.disassemble(addressString, functionLength, false);
		builder.createFunction(addressString);

		prog = builder.getProgram();

		if (decompiler != null) {
			decompiler.dispose();
		}

		decompiler = new DecompInterface();
		decompiler.openProgram(prog);

		decompilation = getDecompilationString(addressString);

		decompilerPORTFVolatile = !decompilation.contains(decompilerPORTFNotVolatileString);
		decompilerPORTGVolatile = !decompilation.contains(decompilerPORTGNotVolatileString);
	}

	private String getDecompilationString(String address) throws AddressFormatException {
		Address addr = prog.getAddressFactory().getDefaultAddressSpace().getAddress(address);
		Function func = prog.getListing().getFunctionAt(addr);
		DecompileResults decompResults = decompiler.decompileFunction(func,
			DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, TaskMonitor.DUMMY);
		return decompResults.getDecompiledFunction().getC();
	}

	@After
	public void tearDown() throws Exception {
		if (decompiler != null) {
			decompiler.dispose();
		}
	}

	@Test
	public void testDecompileInterfaceReturnsAFunction() throws Exception {
		setUp(null, null, false, false);

		Assert.assertNotNull(decompilation);
	}

	@Test
	public void testDecompilePORTFSymbolPspecSettings() throws Exception {
		setUp(null, null, null, false);

		//Decompiler should indicate mem:0x31 is not volatile
		Assert.assertFalse(decompilerPORTFVolatile);

		setUp(false, null, null, false);

		//Decompiler should indicate mem:0x31 is not volatile
		Assert.assertFalse(decompilerPORTFVolatile);

		setUp(true, null, null, false);

		//Decompiler should indicate mem:0x31 is volatile because the symbol element in the language
		//pspec file defined the symbol at mem:0x31 to be volatile.
		Assert.assertTrue(decompilerPORTFVolatile);
	}

	@Test
	public void testDecompilePORTFMemoryPspecSettings() throws Exception {
		setUp(null, null, true, false);

		//Decompiler should indicate mem:0x31 is volatile because the pspec file includes a volatile
		//element that defines the memory location that includes 0x31 as volatile.
		Assert.assertTrue(decompilerPORTFVolatile);

		setUp(null, null, false, false);

		//Decompiler should indicate mem:0x31 is not volatile
		Assert.assertFalse(decompilerPORTFVolatile);

		setUp(null, null, null, false);

		//Decompiler should indicate mem:0x31 is not volatile
		Assert.assertFalse(decompilerPORTFVolatile);

		setUp(false, null, true, false);

		//Decompiler should indicate mem:0x31 is not volatile because the pspec file defines the
		//symbol element PORTF as not volatile and that takes precedence over the pspec's volatile
		//element.
		Assert.assertFalse(decompilerPORTFVolatile);

		setUp(true, null, true, false);

		//Decompiler should indicate mem:0x31 is volatile
		Assert.assertTrue(decompilerPORTFVolatile);

		setUp(false, null, true, true);

		//Decompiler should indicate mem:0x31 is not volatile
		Assert.assertFalse(decompilerPORTFVolatile);
	}

	@Test
	public void testDecompilePORFSizeOverwritesPORTG() throws Exception {
		setUp(true, 1, null, false);

		//Decompiler should indicate mem:0x31 and mem:0x34 are volatile
		Assert.assertTrue(decompilerPORTFVolatile);
		Assert.assertFalse(decompilerPORTGVolatile);

		setUp(false, 4, true, false); //size of 4 addressable units 0x31, 0x32, 0x33 0x34

		//Decompiler should indicate mem:0x31 and mem:0x34 are not volatile
		Assert.assertFalse(decompilerPORTFVolatile);
		Assert.assertFalse(decompilerPORTGVolatile);

		setUp(true, 4, null, false);

		//Decompiler should indicate mem:0x31 and mem:0x34 are volatile
		Assert.assertTrue(decompilerPORTFVolatile);
		Assert.assertTrue(decompilerPORTGVolatile);
	}
}
