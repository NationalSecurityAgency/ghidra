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
package ghidra.trace.database.memory;

import org.junit.Test;

import ghidra.program.model.lang.LanguageID;
import ghidra.trace.util.LanguageTestWatcher.TestLanguage;

public class DBTraceMemoryManagerRegistersPerThreadLETest
		extends AbstractDBTraceMemoryManagerRegistersTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("Toy:LE:64:default");
	}

	@Override
	protected boolean isRegistersPerFrame() {
		return false;
	}

	@Test
	@TestLanguage("Toy:LE:32:builder")
	public void testRegisterBits() throws Exception {
		runTestRegisterBits(b.host);
	}
}
