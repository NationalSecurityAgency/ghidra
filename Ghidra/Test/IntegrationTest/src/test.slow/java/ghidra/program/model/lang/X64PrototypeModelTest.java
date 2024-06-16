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

import java.util.ArrayList;

import org.junit.*;

public class X64PrototypeModelTest extends AbstractProtoModelTest {

	@Before
	public void setUp() throws Exception {
		buildArchitecture("x86:LE:64:default:gcc");
	}

	@Test
	public void testStdCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__stdcall");
		test(model, "void func(int a,int b)", "void,EDI,ESI");
		test(model, "void func(float,float)", "void,XMM0:4,XMM1:4");
		test(model, "void func(short a,int b,char c)", "void,DI,ESI,DX:1");
		test(model, "void func(long,long)", "void,RDI,RSI");
		test(model, "void func(double,double)", "void,XMM0:8,XMM1:8");
		test(model, "void func(int,float,int,float)", "void,EDI,XMM0:4,ESI,XMM1:4");
		test(model, "void func(float,int,float,int)", "void,XMM0:4,EDI,XMM1:4,ESI");
		test(model, "void func(int,double,double,int)", "void,EDI,XMM0:8,XMM1:8,ESI");
		test(model, "void func(double,long,long,double)", "void,XMM0:8,RDI,RSI,XMM1:8");
		test(model, "void func(long double)", "void,stack8:10");
		test(model, "void func(float,long double,float)", "void,XMM0:4,stack8:10,XMM1:4");
		parseStructure("intfloatpair", "int,float");
		test(model, "void func(intfloatpair)", "void,RDI");
		parseStructure("longfloatpair", "long,float");
		test(model, "void func(int,longfloatpair)", "void,EDI,join XMM0:8 RSI");
		parseStructure("longdoublepair", "long,double");
		test(model, "void func(int,longdoublepair)", "void,EDI,join XMM0:8 RSI");
		parseStructure("intdoublepair", "int,double");
		test(model, "void func(int,intdoublepair)", "void,EDI,join XMM0:8 RSI");
		parseStructure("floatintpair", "float,int");
		test(model, "void func(int,floatintpair)", "void,EDI,RSI");
		parseStructure("doubleintpair", "double,int");
		test(model, "void func(int,doubleintpair)", "void,EDI,join RSI XMM0:8");
		parseStructure("intintfloat", "int,int,float");
		test(model, "void func(int,intintfloat)", "void,EDI,join XMM0:4 RSI");
		parseStructure("intintfloatfloat", "int,int,float,float");
		test(model, "void func(int,intintfloatfloat)", "void,EDI,join XMM0:8 RSI");
		parseStructure("intfloatfloatint", "int,float,float,int");
		test(model, "void func(int,intfloatfloatint)", "void,EDI,join RDX RSI");
		parseStructure("intfloatfloat", "int,float,float");
		test(model, "void func(int,intfloatfloat)", "void,EDI,join XMM0:4 RSI");
		parseStructure("floatfloatpair", "float,float");
		test(model, "void func(int,floatfloatpair)", "void,EDI,XMM0:8");
		parseStructure("doublefloatpair", "double,float");
		test(model, "void func(int,doublefloatpair)", "void,EDI,join XMM1:8 XMM0:8");
		parseStructure("floatfloatfloat", "float,float,float");
		test(model, "void func(floatfloatfloat,long)", "void,join XMM1:4 XMM0:8,RDI");
		parseStructure("intintintint", "int,int,int,int");
		test(model, "void func(intintintint)", "void,join RSI RDI");
		test(model, "void func(int,intintintint)", "void,EDI,join RDX RSI");
		parseStructure("intintintintint", "int,int,int,int,int");
		test(model, "void func(intintintintint)", "void,stack8:20");
		test(model, "void func(float,float,float,float,float,float,float,float,longfloatpair)",
			"void,XMM0:4,XMM1:4,XMM2:4,XMM3:4,XMM4:4,XMM5:4,XMM6:4,XMM7:4,stack8:16");
		test(model, "void func(undefined4,undefined8)", "void,EDI,RSI");

		test(model, "intintintint func(void)", "join RDX RAX");
		test(model, "floatintpair func(void)", "RAX");
		test(model, "longfloatpair func(void)", "join XMM0:8 RAX");
		test(model, "longdoublepair func(void)", "join XMM0:8 RAX");
		test(model, "doubleintpair func(void)", "join RAX XMM0:8");
		test(model, "floatfloatfloat func(void)", "join XMM1:4 XMM0:8");
		parseStructure("doubledoublepair", "double,double");
		test(model, "doubledoublepair func(void)", "join XMM1:8 XMM0:8");
		test(model, "floatfloatpair func(void)", "XMM0:8");
		test(model, "intintintintint func(void)", "RAX,RDI");
		parseStructure("doubleintintint", "double,int,int,int");
		test(model, "doubleintintint func(void)", "RAX,RDI");
	}

	@Test
	public void testThisCall() throws Exception {
		PrototypeModel model = cspec.getCallingConvention("__thiscall");
		parseStructure("bigstruct", "int,int,int,int,int");
		PrototypePieces pieces = parseSignature(model, "bigstruct func(int *,int)");
		ArrayList<ParameterPieces> res = new ArrayList<>();
		model.assignParameterStorage(pieces, dtManager, res, true);
		Assert.assertEquals(res.size(), 4);
		Assert.assertTrue(res.get(1).hiddenReturnPtr);
		Assert.assertTrue(res.get(2).isThisPointer);
	}
}
