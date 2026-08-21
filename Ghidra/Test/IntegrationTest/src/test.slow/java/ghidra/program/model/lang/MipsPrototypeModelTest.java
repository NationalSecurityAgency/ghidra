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

public class MipsPrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("MIPS:BE:32:default:default");
	}

	@Test
	public void tesStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall");

		test(model, "void func(short a,int b,char c)", "void,a0:2,a1,a2:1");
		test(model, "void func(double a,double b)", "void,f12_13,f14_15");
		test(model, "void func(float a,float b)", "void,f12,f14");
		test(model, "void func(float a,double b)", "void,f12,f14_15");
		test(model, "void func(double a,float b)", "void,f12_13,f14");
		test(model, "void func(int a,int b,int c,int d)", "void,a0,a1,a2,a3");
		test(model, "void func(double a,int b,double c)", "void,f12_13,a2,stack10:8");
		test(model, "void func(double a,int b,int c)", "void,f12_13,a2,a3");
		test(model, "void func(float a,int b,int c)", "void,f12,a1,a2");
		test(model, "void func(int a,int b,int c,double d)", "void,a0,a1,a2,stack10:8");
		test(model, "void func(int a,int b,int c,float d)", "void,a0,a1,a2,a3");
		test(model, "void func(int a,int b,double c)", "void,a0,a1,join a2 a3");
		test(model, "void func(int a,double b)", "void,a0,join a2 a3");
		test(model, "void func(float a,float b,float c,float d)", "void,f12,f14,a2,a3");
		test(model, "void func(float a,int b,float c,int d)", "void,f12,a1,a2,a3");
		test(model, "void func(double a,float b,float c)", "void,f12_13,f14,a3");
		test(model, "void func(float a,float b,double c)", "void,f12,f14,join a2 a3");
		test(model, "void func(int a,float b,int c,float d)", "void,a0,a1,a2,a3");
		test(model, "void func(int a,float b,int c,int d)", "void,a0,a1,a2,a3");
		test(model, "void func(int a,int b,float c,int d)", "void,a0,a1,a2,a3");

		test(model, "int func(void)", "v0");
		test(model, "float func(void)", "f0");
		test(model, "double func(void)", "f0_1");
		parseStructure("onefieldstruct", "int");
		parseStructure("twofieldstruct", "int,int");
		test(model, "onefieldstruct func(int a)", "v0,a0,a1");
		test(model, "twofieldstruct func(int a)", "v0,a0,a1");
		test(model, "void func(twofieldstruct a)", "void,join a0 a1");

		parseStructure("intdouble", "int,double");
		test(model, "void func(intdouble a)", "void,join a0 a1 a2 a3");
	}
}
