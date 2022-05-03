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
package ghidra.program.database.map;

import java.io.IOException;

import org.junit.Test;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;

public class AddressRangeMap64BitTest extends AbstractAddressRangeMapTest {

	protected ProgramDB createProgram() throws IOException {
		LanguageService service = getLanguageService();
		Language language = service.getLanguage(new LanguageID("sparc:BE:64:default"));
		return new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);
	}

	@Test
	public void testGetValue64BitSpecific() {
		map.paintRange(addr(0), spaceMax, ONE);

		checkValueNoCache(ONE, addr(0x0));
		checkValueNoCache(ONE, addr(0x0));

		// now check addresses that are in different address bases that don't exist yet
		// addresses that differ in the upper 32bits are in different address basesI
		checkValueNoCache(ONE, addr(0xA0000000000000L));
		checkValueNoCache(ONE, addr(0xB0000000000000L));

	}

}
