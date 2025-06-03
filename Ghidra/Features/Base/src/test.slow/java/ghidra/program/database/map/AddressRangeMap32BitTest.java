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

import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.*;

public class AddressRangeMap32BitTest extends AbstractAddressRangeMapTest {

	@Override
	protected ProgramDB createProgram() throws IOException {
		LanguageService service = getLanguageService();
		Language language = service.getLanguage(new LanguageID("sparc:BE:32:default"));
		return new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);
	}

}
