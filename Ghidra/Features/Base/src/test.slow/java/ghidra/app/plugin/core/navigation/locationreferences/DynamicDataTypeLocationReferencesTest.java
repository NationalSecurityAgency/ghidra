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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import ghidra.app.util.datatype.microsoft.RTTI0DataType;
import ghidra.program.model.address.Address;

public class DynamicDataTypeLocationReferencesTest extends AbstractLocationReferencesTest {

	@Test
	public void testDynamicDataType_AddressField_MinAddress() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		createRTTI0DataType(rttiAddr);

		//
		// References: one to each member; no offcut
		//		
		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address field1 = field0.add(4);
		Address from2 = addr(0x01005301);
		createReference(from2, field1);

		Address field2 = field0.add(8);
		Address from3 = addr(0x01005302);
		createReference(from3, field2);

		goToDataAddressField(rttiAddr);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from1, from2, from3);
	}

	@Test
	public void testDynamicDataType_AddressField_MinAddress_Offcut() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		createRTTI0DataType(rttiAddr);

		//
		// References: one regular; 2 offcut
		//		
		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address offcut1 = field0.add(1);
		Address from2 = addr(0x01005301);
		createReference(from2, offcut1);

		Address offcut2 = field0.add(5);
		Address from3 = addr(0x01005302);
		createReference(from3, offcut2);

		goToDataAddressField(rttiAddr);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from1, from2, from3);
	}

	@Test
	public void testDynamicDataType_AddressField_SubData() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		//
		// References: one to each member; no offcut
		//	
		createRTTI0DataType(rttiAddr);

		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address field1 = field0.add(4);
		Address from2 = addr(0x01005301);
		createReference(from2, field1);

		Address field2 = field0.add(8);
		Address from3 = addr(0x01005302);
		createReference(from3, field2);

		goToDataAddressField(field1);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from2);
	}

	@Test
	public void testDynamicDataType_AddressField_SubData_Offcut() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		createRTTI0DataType(rttiAddr);

		//
		// References: one regular; 2 offcut
		//		
		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address offcut1 = field0.add(1);
		Address from2 = addr(0x01005301);
		createReference(from2, offcut1);

		Address offcut2 = field0.add(5);
		Address from3 = addr(0x01005302);
		createReference(from3, offcut2);

		Address field1 = field0.add(4);
		goToDataAddressField(field1);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from3);
	}

	@Test
	public void testDynamicDataType_FieldName_SubData() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		//
		// References: one to each member; no offcut
		//	
		createRTTI0DataType(rttiAddr);

		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address field1 = field0.add(4);
		Address from2 = addr(0x01005301);
		createReference(from2, field1);

		Address field2 = field0.add(8);
		Address from3 = addr(0x01005302);
		createReference(from3, field2);

		goToDataNameFieldAt(field1);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from2);
	}

	@Test
	public void testDynamicDataType_FieldName_SubData_Offcut() throws Exception {

		Address rttiAddr = addr("0x01005470");
		goTo(rttiAddr);

		//
		// References: one to each member; no offcut
		//	
		createRTTI0DataType(rttiAddr);

		Address field0 = rttiAddr;
		Address from1 = addr(0x01005300);
		createReference(from1, field0);

		Address field1 = field0.add(4);
		Address from2 = addr(0x01005301);
		createReference(from2, field1);

		Address offcut1 = field0.add(1);
		Address from3 = addr(0x01005302);
		createReference(from3, offcut1);

		Address offcut2 = field1.add(1);
		Address from4 = addr(0x01005303);
		createReference(from4, offcut2);

		goToDataNameFieldAt(field1);
		search();

		List<LocationReference> results = getResultLocations();
		assertContains(results, from2, from4); // only direct ref and offcut ref to this field
	}
//==================================================================================================
// Private Methods
//==================================================================================================	

	private void createRTTI0DataType(Address addr) throws Exception {

		/*
		   01005470 60 54 00        RTTI_0     DAT_01005460
		            01 64 54 
		            00 01 48 
		       01005470 60 54 00 01     addr      DAT_01005460       vfTablePointer
		       01005474 64 54 00 01     addr      DAT_01005464       dataPointer
		       01005478 48 65 6c 6c 6f  ds        "Hello World!",00  name
		                20 57 6f 72 6c 
		                64 21 00
		       01005485 00 00 00        db[3]                        alignmentBytes
		
		 */

		// bytes: 0x01005460
		// at:    addr
		builder.setBytes(addr.toString(), new byte[] { 0x60, 0x54, 0x00, 0x01 });

		// bytes: 0x01005464
		// at:    addr + 4
		builder.setBytes(addr.add(4).toString(), new byte[] { 0x64, 0x54, 0x00, 0x01 });

		// at:    addr + 8
		createStringBytes(addr.add(8).toString(), "Hello World!");

		RTTI0DataType rtti = new RTTI0DataType();
		createData(addr, rtti);
	}

	private void createStringBytes(String addr, String s) throws Exception {
		byte[] bytes = s.getBytes(StandardCharsets.UTF_8);

		// null terminator
		bytes = Arrays.copyOf(bytes, bytes.length + 1);
		builder.setBytes(addr, bytes);
	}

}
