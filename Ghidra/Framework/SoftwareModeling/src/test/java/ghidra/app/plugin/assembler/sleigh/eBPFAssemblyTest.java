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
package ghidra.app.plugin.assembler.sleigh;

import org.junit.Test;

import ghidra.program.model.lang.LanguageID;

public class eBPFAssemblyTest extends AbstractAssemblyTest {
	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("eBPF:LE:64:default");
	}

	@Test
	public void testAssemble_GOTOX_R2() {
		assertOneCompatRestExact("GOTOX R2", "0d:02:00:00:00:00:00:00");
	}

	@Test
	public void testAssemble_CALLX_R2() {
		assertOneCompatRestExact("CALLX R2", "8d:02:00:00:00:00:00:00");
	}
}
