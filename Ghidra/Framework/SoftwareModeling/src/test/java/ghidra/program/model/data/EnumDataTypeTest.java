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
package ghidra.program.model.data;

import org.junit.*;

import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.UniversalIdGenerator;
import mockit.Expectations;
import mockit.Mocked;

public class EnumDataTypeTest {
	@Mocked
	MemBuffer memBuffer;

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testNegativeValue() throws MemoryAccessException {
		new Expectations() {
			{
				memBuffer.getInt(anyInt);
				result = 0xffffffff;
			}
		};

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0xffffffffL);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));

	}

	@Test
	public void testUpperBitLongValue() throws MemoryAccessException {
		new Expectations() {
			{
				memBuffer.getInt(anyInt);
				result = 0x80000000;
			}
		};

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0x80000000L);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));

	}
}
