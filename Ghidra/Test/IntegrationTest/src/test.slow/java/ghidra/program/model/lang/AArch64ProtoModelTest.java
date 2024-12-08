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

public class AArch64ProtoModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("AARCH64:LE:64:v8A:default");
	}

	@Test
	public void testStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__cdecl");

		test(model, "void func(short a,int b,char c)", "void,w0:2,w1,w2:1");
		test(model, "void func(int, int)", "void,w0,w1");
		test(model, "void func(long,long)", "void,x0,x1");
		test(model, "void func(float,float)", "void,s0,s1");
		test(model, "void func(double,double)", "void,d0,d1");
		test(model, "void func(int,float,int,float)", "void,w0,s0,w1,s1");
		test(model, "void func(float,int,float,int)", "void,s0,w0,s1,w1");
		test(model, "void func(int,double,double,int)", "void,w0,d0,d1,w1");
		test(model, "void func(double,long,long,double)", "void,d0,x0,x1,d1");
		test(model, "void func(float16)", "void,q0");
		test(model, "void func(float,float16)", "void,s0,q1");
		test(model, "void func(int,int,int,int,int,int,int,int,int,int)",
			"void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,stack8:4");
		test(model, "void func(float,float,float,float,float,float,float,float,float,float)",
			"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack8:4");
		test(model, "void func(float,float,float,float,float,float,float,float,float16)",
			"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:16");
		test(model, "void func(float,float,float,float,float,float,float,float,float,float16)",
			"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,stack10:16");
		test(model, "void func(int,int,int,int,int,int,int,int,int,float)",
			"void,w0,w1,w2,w3,w4,w5,w6,w7,stack0:4,s0");
		test(model, "void func(float,float,float,float,float,float,float,float,float,int)",
			"void,s0,s1,s2,s3,s4,s5,s6,s7,stack0:4,w0");

		parseStructure("intpair", "int,int");
		test(model, "void func(intpair)", "void,x0");

		parseStructure("longpair", "long,long");
		test(model, "void func(longpair)", "void,join x1 x0");

		parseStructure("longquad", "long,long,long,long");
		test(model, "void func(longquad)", "void,x0");

		parseStructure("floatdouble", "float,double");
		test(model, "void func(floatdouble)", "void,join x1 x0");

		parseStructure("intfloat", "int,float");
		test(model, "void func(intfloat)", "void,x0");

		parseStructure("longdoublestruct", "long,double");
		test(model, "void func(longdoublestruct)", "void,join x1 x0");

		test(model, "int func()", "w0");
		test(model, "float func()", "s0");
		test(model, "double func()", "d0");

		test(model, "intpair func()", "x0");
		test(model, "longpair func()", "join x1 x0");
		test(model, "longquad func()", "void,x8");

		parseStructure("floatpair", "float,float");
		test(model, "void func(floatpair)", "void,join s1 s0");

		parseStructure("floatpairpair", "floatpair,floatpair");
		test(model, "void func(floatpairpair)", "void,join s3 s2 s1 s0");

		parseStructure("doublequad", "double,double,double,double");
		test(model, "void func(doublequad)", "void,join d3 d2 d1 d0");
	}
}
