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

public class PowerPCPrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("PowerPC:BE:64:default:default");
	}

	@Test
	public void tesStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall");
		test(model, "void func(int a,float b,double c)", "void,r3:4,join f1,f2");
		test(model, "void func(double a,long b,double c)", "void,f1,r4,f2");

		parseStructure("sparm", "int,double");

		String proto =
			"void func(int c,double ff,int d,float16 ld,sparm s,double gg,sparm t,int e,double hh)";
		String res = "void,r3:4,f1,r5:4,join f2 f3,join r8 r9,f4,stack70:16,stack84:4,f5";
		test(model, proto, res);
	}

}
