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

public class Sparc32ProtoModelTest extends AbstractProtoModelTest {
	@Before
	public void setUp() throws Exception {
		buildArchitecture("sparc:BE:32:default:default");
	}

	@Test
	public void testStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall");

		test(model, "void func(int,long long,int,long long,int,int)",
			"void,o0,join o1 o2,o3,o4_5,stack5c:4,stack60:4");

		test(model, "void func(float,double,float,double,float,float)",
			"void,o0,join o1 o2,o3,o4_5,stack5c:4,stack60:4");

		test(model, "void func(int,double,long long,float,float)",
			"void,o0,join o1 o2,join o3 o4,o5,stack5c:4");

		test(model, "void func(int,long double,float)", "void,o0,o1,o2");

		parseStructure("intpair", "int,int");
		test(model, "void func(int,intpair,double)", "void,o0,o1,o2_3");

		test(model, "int func()", "o0");
		test(model, "long long func()", "o0_1");
		test(model, "float func()", "fs0");
		test(model, "double func()", "fd0");
		test(model, "long double func(int,int)", "o0,stack40:4,o0,o1");
		test(model, "intpair func(long long)", "o0,stack40:4,o0_1");
	}

}
