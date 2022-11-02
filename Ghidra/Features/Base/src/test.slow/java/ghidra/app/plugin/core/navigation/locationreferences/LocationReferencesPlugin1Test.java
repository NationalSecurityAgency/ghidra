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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.cmd.data.CreateDataCmd;
import ghidra.app.util.viewer.field.FieldNameFieldFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.util.ProgramLocation;

public class LocationReferencesPlugin1Test extends AbstractLocationReferencesTest {

	@Test
	public void testFieldNameLocationDescriptor_StructureFieldName_ArrayInStructure()
			throws Exception {

		openData(0x01005540);

		goTo(addr(0x01005541), FieldNameFieldFactory.FIELD_NAME, 1);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(StructureMemberLocationDescriptor.class)));
	}

	@Test
	public void testFindStructureField_UnnamedDefaultField() {

		// apply a structure with unnamed fields
		Structure struct = (Structure) getDt("/MyStruct");
		Address address = addr(0x01005560);
		assertTrue(applyCmd(program, new CreateDataCmd(address, struct)));

		openData(0x01005560);

		goTo(addr(0x01005560), FieldNameFieldFactory.FIELD_NAME, 1);

		ProgramLocation location = codeBrowser.getCurrentLocation();
		LocationDescriptor descriptor = ReferenceUtils.getLocationDescriptor(location);
		assertThat(descriptor, is(instanceOf(StructureMemberLocationDescriptor.class)));
	}

	@Test
	public void testFindEnumByMember() {

		//
		// This test searches for usage of an enum field.  We will add two different enum field
		// uses to make sure we only find the one for which we are searching.
		//

		Enum enoom = createEnum();
		Address otherAddress = addr(0x01008014); // 0x1  ONE; this also has references
		assertTrue(applyCmd(program, new CreateDataCmd(otherAddress, enoom)));

		// this is the address will will use to search
		Address address = addr(0x01008019); // 0x0  ZERO		
		assertTrue(applyCmd(program, new CreateDataCmd(address, enoom)));

		goTo(address, "Operands", 1);

		search();

		assertResultCount(1);
	}

	private DataType getDt(String path) {
		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = dtm.getDataType(path);
		return dataType;
	}

	private Enum createEnum() {
		return tx(program, () -> {
			ProgramBasedDataTypeManager dtm = program.getDataTypeManager();
			Enum dt = new EnumDataType("TestEnum", 1);
			dt.add("ZERO", 0);
			dt.add("ONE", 1);
			dt.add("TWO", 2);
			return (Enum) dtm.addDataType(dt, null);
		});
	}
}
