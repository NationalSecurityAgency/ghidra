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
package sarif;

import org.junit.Test;

import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.util.LongPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.VoidPropertyMap;
import ghidra.program.util.ProgramDiff;
import ghidra.util.SaveableColor;

public class PropertiesSarifTest extends AbstractSarifTest {

	public PropertiesSarifTest() {
		super();
	}

	@Test
	public void testPropertyMaps() throws Exception {
		block.putBytes(entry, asm, 0, asm.length);

		PropertyMapManager propertyManager = program.getUsrPropertyManager();
		LongPropertyMap longMap = propertyManager.createLongPropertyMap("LongMap");
		longMap.add(entry.add(3), 6L);
		longMap.add(entry.add(4), 12L);
		VoidPropertyMap voidMap = propertyManager.createVoidPropertyMap("VoidMap");
		voidMap.add(entry.add(10));
		
		builder.setIntProperty(entry.add(1).toString(), "IntMap", 5);
		builder.setIntProperty(entry.add(2).toString(), "IntMap", 10);
		builder.setStringProperty(entry.add(5).toString(), "StringMap", "TESTING");
		builder.setStringProperty(entry.add(6).toString(), "StringMap", "1");
		builder.setObjectProperty(entry.add(7).toString(), "ObjectMap", new SaveableColor(Palette.CYAN));
		builder.setObjectProperty(entry.add(8).toString(), "ObjectMap", new SaveableColor(Palette.BLACK));

		ProgramDiff programDiff = readWriteCompare();
		
		AddressSetView differences = programDiff.getDifferences(monitor);
		assert(differences.isEmpty());
	}

//	@Test
//	public void testPropertyList() throws Exception {
//		block.putBytes(entry, asm, 0, asm.length);
//
//		ProgramDiff programDiff = readWriteCompare();
//		
//		AddressSetView differences = programDiff.getDifferences(monitor);
//		assert(differences.isEmpty());
//	}
}
