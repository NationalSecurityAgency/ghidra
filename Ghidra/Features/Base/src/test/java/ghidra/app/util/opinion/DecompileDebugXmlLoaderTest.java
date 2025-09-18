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
/**
 * 
 */
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.File;
import java.math.BigInteger;
import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.DecompileDebugXmlLoader.DecompileDebugProgramInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import resources.ResourceManager;

/**
 *
 */
public class DecompileDebugXmlLoaderTest extends AbstractGhidraHeadedIntegrationTest {
	private File decompileDebugTestFile;
	private ProgramLoader.Builder programLoader;

	@Before
	public void setUp() {
		String DECOMPILE_DEBUG_TEST_FILE = "ghidra/app/util/opinion/decompile_debug_test.xml";
		decompileDebugTestFile = ResourceManager.getResourceFile(DECOMPILE_DEBUG_TEST_FILE);
		programLoader = ProgramLoader.builder()
				.source(decompileDebugTestFile)
				.loaders(DecompileDebugXmlLoader.class);
	}

	/**
	 * Test method for {@link ghidra.app.util.opinion.DecompileDebugFormatManager#getProgramInfo()}.
	 * 
	 * @throws Exception if an error occurred
	 */
	@Test
	public void testDecompileDebugXmlLoad() throws Exception {
		try (LoadResults<Program> loadResults = programLoader.load()) {
			assertTrue("expected single loaded program", loadResults.size() == 1);
		}
	}

	@Test
	public void testVerifyProgramInfo() throws Exception {
		DecompileDebugFormatManager mngr = new DecompileDebugFormatManager(decompileDebugTestFile);
		DecompileDebugProgramInfo progInfo = mngr.getProgramInfo();
		assertEquals("Spec string should be parsed correctly", "x86:LE:64:default",
			progInfo.specString());
		assertEquals("Compiler string should be extracted separately", "gcc",
			progInfo.compilerString());
		assertEquals("Memory offset should be parsed from the offset tag", "0x140022cb8",
			progInfo.offset());
	}

	@Test
	public void testVerifyLoadedProgramBytes() throws Exception {
		try (LoadResults<Program> loadResults = programLoader.load()) {
			Program program = loadResults.getPrimaryDomainObject(this);
			try {
				assertEquals("gcc", program.getCompilerSpec().getCompilerSpecID().toString());

				Memory memory = program.getMemory();
				MemoryBlock[] blocks = memory.getBlocks();
				assertEquals(26, blocks.length);

				// Verify memory blocks
				verifyBlock(blocks[0], "decompile_debug_test.xml", true,
					getAddr(program, new BigInteger("140000000", 16)), 128);
				verifyBlock(blocks[1], "__scrt_acquire_startup_lock", true,
					getAddr(program, new BigInteger("1400227f8", 16)), 1);
				verifyBlock(blocks[2], "FUN_140022834", true,
					getAddr(program, new BigInteger("140022834", 16)), 1);
				verifyBlock(blocks[3], "FUN_1400228fc", true,
					getAddr(program, new BigInteger("1400228fc", 16)), 1);
				verifyBlock(blocks[4], "__scrt_release_startup_lock", true,
					getAddr(program, new BigInteger("140022994", 16)), 1);
				verifyBlock(blocks[5], "__scrt_uninitialize_crt", true,
					getAddr(program, new BigInteger("1400229b8", 16)), 1);
				verifyBlock(blocks[6], "decompile_debug_test.xml", true,
					getAddr(program, new BigInteger("140022cb8", 16)), 296);
				verifyBlock(blocks[7], "decompile_debug_test.xml", true,
					getAddr(program, new BigInteger("140022df9", 16)), 39);
			}
			finally {
				program.release(this);
			}
		}
	}

	@Test
	public void testVerifyLoadedProgramDataTypes() throws Exception {
		try (LoadResults<Program> loadResults = programLoader.load()) {
			Program program = loadResults.getPrimaryDomainObject(this);
			try {
				// Verify data type generation
				ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
				assertEquals("Category count didn't match. ", 2, dtm.getCategoryCount());

				Iterator<Structure> structures = dtm.getAllStructures();
				Structure struct = structures.next(); // there is only 1 struct in the example XML dump
				assertEquals("Component count didn't match.", 20, struct.getNumComponents());
				assertEquals("Struct name is incorrect", "IMAGE_DOS_HEADER", struct.getName());
				DataTypeComponent array = struct.getComponentAt(0); // the first component is an array
				assertEquals("Array component name doesn't match", "e_magic", array.getFieldName());
				assertEquals("Array wasn't sized right", 2, array.getLength());
			}
			finally {
				program.release(this);
			}
		}
	}

	@Test
	public void verifyLoadedProgramFunctions() throws Exception {
		try (LoadResults<Program> loadResults = programLoader.load()) {
			Program program = loadResults.getPrimaryDomainObject(this);
			try {
				// Verify function collection
				FunctionManager funcMngr = program.getFunctionManager();
				assertEquals("Function count doesn't match", 19, funcMngr.getFunctionCount());

				Iterator<Function> functions = funcMngr.getFunctions(true);
				Function function = functions.next(); // this is the function the dump was made for; the others are references
				assertEquals("Function name needs to match.", "__scrt_acquire_startup_lock",
					function.getName());
			}
			finally {
				program.release(this);
			}
		}
	}

	private void verifyBlock(MemoryBlock block, String name, boolean initialized, Address min,
			long length) {
		assertEquals("Name should match", name, block.getName());
		assertEquals("Initalization didn't match", initialized, block.isInitialized());
		assertEquals("Start address didn't match", min, block.getStart());
		assertEquals("Block length didn't match", length, block.getSize());
	}

	private Address getAddr(Program program, BigInteger offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset.longValue());
	}
}
