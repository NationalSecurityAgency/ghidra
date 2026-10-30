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
package ghidra.app.util.bin.format.dwarf;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.util.bin.format.dwarf.expression.DWARFExpressionValueException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.Varnode;

public class DWARFStackValueReaderTest extends DWARFTestBase {

	private DWARFFunction function(byte[] code) throws Exception {
		program.getMemory().setBytes(addr(0x410), code);
		DebugInfoEntry die = newSubprogram("test", addInt(), 0x410, code.length).create();
		importAllDataTypes();
		return DWARFFunction.read(getAggregate(die));
	}

	private Varnode register(String name) {
		Register reg = program.getRegister(name);
		return new Varnode(reg.getAddress(), reg.getMinimumByteSize());
	}

	private void checkStackFrame(int frameSize) throws Exception {
		DWARFFunction function = function(new byte[] {
			0x48, (byte) 0x83, (byte) 0xec, (byte) frameSize, (byte) 0x90 });
		Varnode value = (Varnode) new DWARFStackValueReader(function, 4, false).getValue(register("RSP"));
		assertTrue(value.getAddress().isStackAddress());
		assertEquals(-frameSize, value.getOffset());
		assertNull(program.getListing().getInstructionAt(addr(0x410)));
	}

	@Test
	public void testStackFrame16() throws Exception {
		checkStackFrame(16);
	}

	@Test
	public void testStackFrame32() throws Exception {
		checkStackFrame(32);
	}

	@Test
	public void testStackFrame48() throws Exception {
		checkStackFrame(48);
	}

	@Test
	public void testFramePointer() throws Exception {
		DWARFFunction function = function(new byte[] {
			0x55, 0x48, (byte) 0x89, (byte) 0xe5,
			0x48, (byte) 0x83, (byte) 0xec, 0x20, (byte) 0x90 });
		DWARFStackValueReader reader = new DWARFStackValueReader(function, 8, false);
		assertEquals(-8, ((Varnode) reader.getValue(register("RBP"))).getOffset());
		assertEquals(-40, ((Varnode) reader.getValue(register("RSP"))).getOffset());
	}

	@Test(expected = DWARFExpressionValueException.class)
	public void testUnknownRegister() throws Exception {
		DWARFFunction function = function(new byte[] { (byte) 0x90, (byte) 0x90 });
		new DWARFStackValueReader(function, 1, false).getValue(register("RAX"));
	}

	@Test(expected = DWARFExpressionValueException.class)
	public void testRejectBranch() throws Exception {
		DWARFFunction function = function(new byte[] { (byte) 0xeb, 0, (byte) 0x90 });
		new DWARFStackValueReader(function, 2, false).getValue(register("RSP"));
	}

	@Test(expected = DWARFExpressionValueException.class)
	public void testRejectOutsideFunction() throws Exception {
		DWARFFunction function = function(new byte[] { (byte) 0x90 });
		new DWARFStackValueReader(function, 2, false).getValue(register("RSP"));
	}

	@Test(expected = DWARFExpressionValueException.class)
	public void testWildcardCacheDoesNotAliasNegativeRange() throws Exception {
		DWARFFunction function = function(new byte[] { (byte) 0x90 });
		DWARFStackValueReader wildcard = function.getStackValueReader(0, true);
		DWARFStackValueReader ranged = function.getStackValueReader(-1, false);
		assertNotSame(wildcard, ranged);
		ranged.getValue(register("RSP"));
	}

	@Test
	public void testExplicitEntryRangeUsesEntryStack() throws Exception {
		DWARFFunction function = function(new byte[] {
			0x48, (byte) 0x83, (byte) 0xec, 0x20, (byte) 0x90 });
		DWARFStackValueReader reader = new DWARFStackValueReader(function, 0, false);
		assertEquals(0, ((Varnode) reader.getValue(register("RSP"))).getOffset());
		assertTrue(reader.isFrameBaseValid(new DWARFLocation(0x410, 0x414, new byte[0])));
		assertFalse(reader.isFrameBaseValid(new DWARFLocation(0x414, 0x415, new byte[0])));
	}

	@Test(expected = DWARFExpressionValueException.class)
	public void testRejectMissingPrologueEnd() throws Exception {
		DWARFFunction function = function(new byte[] { (byte) 0x90 });
		new DWARFStackValueReader(function, 0, true).getValue(register("RSP"));
	}
}
