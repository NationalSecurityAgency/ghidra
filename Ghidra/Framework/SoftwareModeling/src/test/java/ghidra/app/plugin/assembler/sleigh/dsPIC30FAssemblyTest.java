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

import org.junit.Ignore;
import org.junit.Test;

import ghidra.program.model.lang.LanguageID;

public class dsPIC30FAssemblyTest extends AbstractAssemblyTest {

	@Override
	protected LanguageID getLanguageID() {
		return new LanguageID("dsPIC30F:LE:24:default");
	}

	@Test
	public void testAssemble_call_W0() {
		assertOneCompatRestExact("call W0", "00:00:01:00", 0x000100);
	}

	@Test
	@Ignore("Fails because W4 is a valid label, but the wrong 'size'")
	public void testAssemble_clr_b_W4() {
		assertOneCompatRestExact("clr.b W4", "00:42:eb:00", 0x000100);
	}
}
