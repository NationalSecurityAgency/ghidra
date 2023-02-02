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
package ghidra.program.database;

import org.junit.Assert;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguageVolatilityTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

public class ProgramVolatilityTest extends SleighLanguageVolatilityTest {
	private Program prog;
	String PORTFAddressString = "mem:0x31";
	String PORTGAddressString = "mem:0x34";
	
	boolean isPORTFVolatile;
	boolean isPORTFMemoryVolatile;
	boolean isPORTGVolatile;
	boolean isPORTGMemoryVolatile;
	boolean isPORTFDataVolatile;
	boolean isPORTGDataVolatile;
	
	public void setUp(Boolean symbolVolatile, Integer symbolSize, Boolean memoryVolatile, boolean reverse) throws Exception {
		super.setUp(symbolVolatile, symbolSize, memoryVolatile, reverse);
		
		ProgramBuilder builder = new ProgramBuilder("test", lang);
		builder.createMemory("PORTF", "mem:0x31", 2); //last parameter is block length
		builder.createMemory("PORTG", "mem:0x34", 2);
		
		prog = builder.getProgram();
		
		Address PORTFAddress = prog.getAddressFactory().getAddress(PORTFAddressString);
		Address PORTGAddress = prog.getAddressFactory().getAddress(PORTGAddressString);
		MemoryBlock PORTFMemoryBlock = prog.getMemory().getBlock(PORTFAddress);
		MemoryBlock PORTGMemoryBlock = prog.getMemory().getBlock(PORTGAddress);
		Data PORTFData = prog.getListing().getDataAt(PORTGAddress);
		Data PORTGData = prog.getListing().getDataAt(PORTGAddress);
		
		isPORTFVolatile = lang.isVolatile(PORTFAddress);
		isPORTFMemoryVolatile = PORTFMemoryBlock.isVolatile();
		isPORTFDataVolatile = PORTFData.isVolatile();
		
		isPORTGVolatile = lang.isVolatile(PORTGAddress);
		isPORTGMemoryVolatile = PORTGMemoryBlock.isVolatile();
		isPORTGDataVolatile = PORTGData.isVolatile();
	}
	
	@Test
	public void testProgramPORTFDefined() throws Exception {
		setUp(null, null, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(false, null, null, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(true, null, null, false);
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
	}
	
	@Test
	public void testProgramPORTFSizeDefined() throws Exception {
		setUp(null, 1, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertFalse(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
		
		setUp(false, 1, null, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertFalse(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
		
		setUp(true, 1, null, false);
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertFalse(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
		
		setUp(null, 4, null, false);

		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertFalse(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
		
		setUp(false, 4, null, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertFalse(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
		
		setUp(true, 4, null, false); // setting portf to size 4 overwrites portg as well
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		Assert.assertTrue(isPORTGVolatile);
		Assert.assertFalse(isPORTGMemoryVolatile);
		Assert.assertFalse(isPORTGDataVolatile);
	}
	
	@Test
	public void testProgramMemoryDefinedVolatile() throws Exception {
		setUp(null, null, null, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(null, null, false, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(null, null, true, false);
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
	}
	
	@Test
	public void testProgramPORTFandMemoryDefined() throws Exception {
		setUp(true, null, true, false);
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(false, null, true, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(true, null, false, false);
		
		Assert.assertTrue(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
		
		setUp(false, null, false, false);
		
		Assert.assertFalse(isPORTFVolatile);
		Assert.assertFalse(isPORTFMemoryVolatile);
		Assert.assertFalse(isPORTFDataVolatile);
	}
	
}
