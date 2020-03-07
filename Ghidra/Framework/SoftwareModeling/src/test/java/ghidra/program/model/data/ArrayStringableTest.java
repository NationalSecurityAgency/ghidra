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

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGTest;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.mem.ByteMemBufferImpl;

public class ArrayStringableTest extends AbstractGTest {
	private ByteMemBufferImpl mb(boolean isBE, int... values) {
		GenericAddressSpace gas = new GenericAddressSpace("test", 32, AddressSpace.TYPE_RAM, 1);
		return new ByteMemBufferImpl(gas.getAddress(0), bytes(values), isBE);
	}

	private SettingsBuilder newset() {
		return new SettingsBuilder();
	}

	private static class DataOrgDTM extends TestDummyDataTypeManager {
		private DataOrganization dataOrg;

		public DataOrgDTM(int charSize) {
			DataOrganizationImpl dataOrgImpl = DataOrganizationImpl.getDefaultOrganization(null);
			dataOrgImpl.setCharSize(charSize);

			this.dataOrg = dataOrgImpl;
		}

		@Override
		public DataOrganization getDataOrganization() {
			return dataOrg;
		}
	}

	private Array mkArray(DataTypeManager dtm, int count) {
		CharDataType charDT = new CharDataType(dtm);
		Array arrayDT = new ArrayDataType(charDT, count, charDT.getLength(), dtm);

		return arrayDT;
	}


	private Array array10char1 = mkArray(new DataOrgDTM(1), 10);
	private Array array10char2 = mkArray(new DataOrgDTM(2), 10);
	private Array array6char4 = mkArray(new DataOrgDTM(4), 6);
	private Array array10char5 = mkArray(new DataOrgDTM(5), 3);

	//-------------------------------------------------------------------------------------
	// get string rep of an array of various sized character elements
	//-------------------------------------------------------------------------------------
	@Test
	public void testGetRep_1bytechar() {
		// because the char size is 1, default charset will be us-ascii, which matches character element size
		ByteMemBufferImpl buf = mb(false, 'h', 'e', 'l', 'l', 'o', 0, 'x', 'y', 0, 0);

		assertEquals("\"hello\"",
			array10char1.getRepresentation(buf, newset(), array10char1.getLength()));
	}

	@Test
	public void testGetRep_2bytechar() {
		// because char size is 2, default charset will be utf-16, which matches character element size
		ByteMemBufferImpl buf =
			mb(false, 'h', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, 0, 0, 'x', 'y', 0, 0, 0, 0, 0, 0);

		assertEquals("u\"hello\"",
			array10char2.getRepresentation(buf, newset(), array10char2.getLength()));
	}

	@Test
	public void testGetRep_4bytechar() {
		// because char size is 4, default charset will be utf-32, which matches character element size
		ByteMemBufferImpl buf = mb(false, 'h', 0, 0, 0, 'e', 0, 0, 0, 'l', 0, 0, 0, 'l', 0, 0, 0,
			'o', 0, 0, 0, 0, 0, 0, 0, 'x', 'y', 0, 0, 0, 0, 0, 0);

		assertEquals("U\"hello\"",
			array6char4.getRepresentation(buf, newset(), array6char4.getLength()));
	}

	@Test
	public void testGetRep_5bytechar() {
		// because the char size isn't normal, charset will default to us-ascii, which does not match
		// the element size of the array, triggering padding-removal in the stringdatainstance code.
		ByteMemBufferImpl buf =
			mb(false, 'h', 'x', 'x', 'x', 'x', 'e', 'x', 'x', 'x', 'x', 0, 0, 0, 0, 0);

		assertEquals("\"he\"",
			array10char5.getRepresentation(buf, newset(), array10char5.getLength()));
	}
}
