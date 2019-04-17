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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

import ghidra.app.util.viewer.field.FieldNameFieldFactory;
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
}
