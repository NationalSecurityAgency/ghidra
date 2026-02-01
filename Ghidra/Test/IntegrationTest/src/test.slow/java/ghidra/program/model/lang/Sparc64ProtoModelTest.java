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

public class Sparc64ProtoModelTest extends AbstractProtoModelTest {
	@Before
	public void setUp() throws Exception {
		buildArchitecture("sparc:BE:64:default:default");
	}

	@Test
	public void testStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall");

		test(model, "void func(int,long long,int,long long,int,int,int)",
			"void,o0:4,o1,o2:4,o3,o4:4,o5:4,stack8b3:4");

		// extra checks of floating point mixed with integer types
		// is to ensure that floating point and integer types with consume the
		// space for the opposite type
		test(model, "void func(float,float,char)", "void,fs1,fs3,o2:1");

		test(model, "void func(double,double)", "void,fd0,fd2");

		test(model, "void func(long double,int)", "void,fq0,o4:4");

		test(model, "void func(int,double,float,long long)", "void,o0:4,fd2,fs5,o3");

		test(model, "void func(float,double,float,double,float,float)",
			"void,fs1,fd2,fs5,fd6,fs9,fs11");

		test(model, "void func(int,double,long long,float,float)",
			"void,o0:4,fd2,o2,fd6:4,fs9");

		test(model, "void func(int,double,long long,float,float)",
			"void,o0:4,fd2,o2,fs7,fs9");

		test(model, "char func()", "o0:1");
		test(model, "int func()", "o0:4");
		test(model, "long long func()", "o0");
		test(model, "float func()", "fs1");
		test(model, "double func()", "fd0");

		// structures passed as pointer arguments
		parseStructure("intpair", "int,int");
		test(model, "void func(int,intpair,double)", "void,o0:4,o1,fd4");

		// hidden return of structure
		test(model, "intpair func(long long)", "o0,stack7ef:8,o0");

		test(model, "long double func(int,int)", "fq0,o0:4,o1:4");

	}

}
