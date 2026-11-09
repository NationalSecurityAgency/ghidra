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
package ghidra.program.model.lang;

import org.junit.Before;
import org.junit.Test;

public class X86Pascal16PrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("x86:LE:16:Real Mode:default");
	}

	@Test
	public void testPascalNear() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__pascal16near");

		test(model, "void func(short a)", "void,stack2:2");
		test(model, "void func(short a,short b)", "void,stack4:2,stack2:2");
		test(model, "void func(short a,short b,short c)", "void,stack6:2,stack4:2,stack2:2");
	}

	@Test
	public void testPascalFar() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__pascal16far");

		test(model, "void func(short a,short b)", "void,stack6:2,stack4:2");
	}

	@Test
	public void testStdcallNear() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall16near");

		test(model, "void func(short a,short b)", "void,stack2:2,stack4:2");
	}
}
