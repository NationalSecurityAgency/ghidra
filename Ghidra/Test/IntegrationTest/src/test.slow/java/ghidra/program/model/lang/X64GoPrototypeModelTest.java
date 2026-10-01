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

public class X64GoPrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("x86:LE:64:default:golang");
	}

	@Test
	public void testAbiInternal() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("abi-internal");

		test(model, "void func(short a,int b,char c)", "void,AX,RBX,CL");
		test(model, "void func(float a,float b)", "void,XMM0:4,XMM1:4");
		test(model, "void func(float a,double c)", "void,XMM0:4,XMM1:8");
		test(model,
			"void func(int a,int b,int c,int d,int e,float f,float g,int h,int i,int j,int k,int l)",
			"void,RAX,RBX,RCX,RDI,RSI,XMM0:4,XMM1:4,R8,R9,R10,R11,stack8:8");
		test(model,
			"void func(float a,float b,float c,float d,float e,float f,float g,float h," +
				"float i,float j,float k,float l,float m,float n,float o,float p)",
			"void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,XMM8:4," +
				"XMM9:4,XMM10:4,XMM11:4,XMM12:4,XMM13:4,XMM14:4,stack8:4");
		test(model, "void func(int a,int[3] b,int c)", "void,RAX,stack8:24,RBX");
		parseStructure("Person", "bool,int32_t");
		parseStructure("Myriad", "int,bool,Person,float");
		test(model, "void func(Person a)", "void,join EBX pad:3 AL");
		test(model, "void func(bool a,Myriad b)", "void,AL,join XMM0:4 ESI pad:3 DIL pad:3 CL RBX");
		test(model, "Person func(void)", "join EBX pad:3 AL");
		test(model, "double[5] func(int a,int[10] b)", "stack58:40,RAX,stack8:80");
		test(model, "char[5] func(char[3] a,char[7] b,int c)", "stack18:5,stack8:3,stackb:7,RAX");
		test(model, "void func(float a,int[1] b,int[2] c)", "void,XMM0:4,RAX,stack8:16");
	}

}
