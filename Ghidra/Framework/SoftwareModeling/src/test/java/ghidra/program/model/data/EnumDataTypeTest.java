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

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.ByteMemBufferImpl;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.UniversalIdGenerator;

public class EnumDataTypeTest {

	@Before
	public void setUp() {
		UniversalIdGenerator.initialize();
	}

	@Test
	public void testNegativeValue() {

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0xffffffffL);

		ByteMemBufferImpl memBuffer = new ByteMemBufferImpl(Address.NO_ADDRESS,
			BigEndianDataConverter.INSTANCE.getBytes(-1), true);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));

	}

	@Test
	public void testUpperBitLongValue() {

		EnumDataType enumDt = new EnumDataType("Test", 4);
		enumDt.add("bob", 0x80000000L);

		ByteMemBufferImpl memBuffer = new ByteMemBufferImpl(Address.NO_ADDRESS,
			BigEndianDataConverter.INSTANCE.getBytes(Integer.MIN_VALUE), true);

		Assert.assertEquals("bob", enumDt.getRepresentation(memBuffer, null, 0));

	}
}
