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
package ghidra.app.util.demangler.swift;

import static org.junit.Assert.*;
import static org.junit.Assume.*;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemangledStructure;
import ghidra.util.exception.AssertException;

/**
 * Unit tests for the {@link SwiftDemangler}.  Requires Swift to be installed on the test system.
 * If it is not, these tests will be skipped.
 */
public class SwiftDemanglerTest extends AbstractGenericTest {

	private SwiftDemangler demangler;

	@Before
	public void setUp() throws Exception {
		demangler = new SwiftDemangler();

		// Ghidra does not ship the native Swift demangler binary, so it may not be present to run 
		// these tests. In this scenario, we just want these tests skipped (as opposed to failing).
		try {
			new SwiftNativeDemangler(new SwiftDemanglerOptions().getSwiftDir());
		}
		catch (IOException e) {
			assumeNoException(e); // skip test, don't fail
		}
	}

	@Test
	public void testFunctionAndTypes() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Function
		    kind=Module, text="SwiftDemanglerTest"
		    kind=Identifier, text="testJunitFunctionAndTypes"
		    kind=LabelList
		      kind=FirstElementMarker
		      kind=Identifier, text="label2"
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=Identifier, text="label14"
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		      kind=FirstElementMarker
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=InOut
		                    kind=Structure
		                      kind=Module, text="Swift"
		                      kind=Identifier, text="Int"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int8"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int16"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int32"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int64"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="UInt"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="UInt8"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="UInt16"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="UInt32"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="UInt64"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Float"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Float"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Double"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Double"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="String"
		              kind=TupleElement
		                kind=Type
		                  kind=BoundGenericStructure
		                    kind=Type
		                      kind=Structure
		                        kind=Module, text="Swift"
		                        kind=Identifier, text="Array"
		                    kind=TypeList
		                      kind=Type
		                        kind=Structure
		                          kind=Module, text="Swift"
		                          kind=Identifier, text="Int"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Bool"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Character"
		        kind=ReturnType
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Float"
		SwiftDemanglerTest.testJunitFunctionAndTypes(_: inout Swift.Int, label2: Swift.Int8, _: Swift.Int16, _: Swift.Int32, _: Swift.Int64, _: Swift.UInt, _: Swift.UInt8, _: Swift.UInt16, _: Swift.UInt32, _: Swift.UInt64, _: Swift.Float, _: Swift.Float, _: Swift.Double, label14: Swift.Double, _: Swift.String, _: [Swift.Int], _: Swift.Bool, _: Swift.Character) -> (Swift.Int, Swift.Float)
		**********************************************************************/
		String mangled =
			"_$s18SwiftDemanglerTest25testJunitFunctionAndTypes_6label2___________7label14____Si_SftSiz_s4Int8Vs5Int16Vs5Int32Vs5Int64VSus5UInt8Vs6UInt16Vs6UInt32Vs6UInt64VS2fS2dSSSaySiGSbSJtF";
		String demangled =
			"struct tuple2 default SwiftDemanglerTest::testJunitFunctionAndTypes(int *,__int8 label2,__int16,__int32,__int64,unsigned int,unsigned __int8,unsigned __int16,unsigned __int32,unsigned __int64,float,float,double,double label14,struct Swift::String,Swift::Array<int>[],bool,struct Swift::Character)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());

		if (!(function.getReturnType() instanceof DemangledStructure struct)) {
			throw new AssertException("Demangled return type is not a structure");
		}
		assertEquals(struct.getFields().size(), 2);
		assertEquals(struct.getFields().get(0).type().toString(), "int");
		assertEquals(struct.getFields().get(1).type().toString(), "float");
	}

	@Test
	public void testStructureAllocator() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Allocator
		    kind=Structure
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyStructure"
		    kind=LabelList
		      kind=Identifier, text="label1"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Structure
		              kind=Module, text="SwiftDemanglerTest"
		              kind=Identifier, text="MyStructure"
		SwiftDemanglerTest.MyStructure.init(label1: Swift.Int) -> SwiftDemanglerTest.MyStructure
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureV6label1ACSi_tcfC";
		String demangled =
			"struct SwiftDemanglerTest::MyStructure default SwiftDemanglerTest::MyStructure::init(int label1)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testStructureFunction() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Function
		    kind=Structure
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyStructure"
		    kind=Identifier, text="myMethod"
		    kind=LabelList
		      kind=Identifier, text="label1"
		      kind=Identifier, text="label2"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Structure
		              kind=Module, text="Swift"
		              kind=Identifier, text="Int"
		SwiftDemanglerTest.MyStructure.myMethod(label1: Swift.Int, label2: Swift.Int) -> Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureV8myMethod6label16label2S2i_SitF";
		String demangled =
			"int default SwiftDemanglerTest::MyStructure::myMethod(int label1,int label2,struct SwiftDemanglerTest::MyStructure)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testStructureGetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Getter
		    kind=Variable
		      kind=Structure
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyStructure"
		      kind=Identifier, text="z"
		      kind=Type
		        kind=Structure
		          kind=Module, text="Swift"
		          kind=Identifier, text="Int"
		SwiftDemanglerTest.MyStructure.z.getter : Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureV1zSivg";
		String demangled =
			"int default SwiftDemanglerTest::MyStructure::get_z(struct SwiftDemanglerTest::MyStructure)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testStructureSetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Setter
		    kind=Variable
		      kind=Structure
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyStructure"
		      kind=Identifier, text="z"
		      kind=Type
		        kind=Structure
		          kind=Module, text="Swift"
		          kind=Identifier, text="Int"
		SwiftDemanglerTest.MyStructure.z.setter : Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureV1zSivs";
		String demangled = "__thiscall SwiftDemanglerTest::MyStructure::set_z(int)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testStructureSubscriptGetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Getter
		    kind=Subscript
		      kind=Structure
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyStructure"
		      kind=LabelList
		      kind=Type
		        kind=FunctionType
		          kind=ArgumentTuple
		            kind=Type
		              kind=Structure
		                kind=Module, text="Swift"
		                kind=Identifier, text="Int"
		          kind=ReturnType
		            kind=Type
		              kind=Structure
		                kind=Module, text="Swift"
		                kind=Identifier, text="Int"
		SwiftDemanglerTest.MyStructure.subscript.getter : (Swift.Int) -> Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureVyS2icig";
		String demangled =
			"int default SwiftDemanglerTest::MyStructure::get_subscript(int,struct SwiftDemanglerTest::MyStructure)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testStructureSubscriptSetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Setter
		    kind=Subscript
		      kind=Structure
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyStructure"
		      kind=LabelList
		      kind=Type
		        kind=FunctionType
		          kind=ArgumentTuple
		            kind=Type
		              kind=Structure
		                kind=Module, text="Swift"
		                kind=Identifier, text="Int"
		          kind=ReturnType
		            kind=Type
		              kind=Structure
		                kind=Module, text="Swift"
		                kind=Identifier, text="Int"
		SwiftDemanglerTest.MyStructure.subscript.setter : (Swift.Int) -> Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest11MyStructureVyS2icis";
		String demangled = "int __thiscall SwiftDemanglerTest::MyStructure::set_subscript(int)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassTypeMetadataAccessor() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=TypeMetadataAccessFunction
		    kind=Type
		      kind=Class
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyClass"
		type metadata accessor for SwiftDemanglerTest.MyClass
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassCMa";
		String demangled =
			"class SwiftDemanglerTest::MyClass * default SwiftDemanglerTest::MyClass::typeMetadataAccessor(void)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassAllocator() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Allocator
		    kind=Class
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyClass"
		    kind=LabelList
		      kind=Identifier, text="label1"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Class
		              kind=Module, text="SwiftDemanglerTest"
		              kind=Identifier, text="MyClass"
		SwiftDemanglerTest.MyClass.__allocating_init(label1: Swift.Int) -> SwiftDemanglerTest.MyClass
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC6label1ACSi_tcfC";
		String demangled =
			"class SwiftDemanglerTest::MyClass * __thiscall SwiftDemanglerTest::MyClass::__allocating_init(int label1)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassConstructor() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Constructor
		    kind=Class
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyClass"
		    kind=LabelList
		      kind=Identifier, text="label1"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Class
		              kind=Module, text="SwiftDemanglerTest"
		              kind=Identifier, text="MyClass"
		SwiftDemanglerTest.MyClass.init(label1: Swift.Int) -> SwiftDemanglerTest.MyClass
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC6label1ACSi_tcfc";
		String demangled =
			"class SwiftDemanglerTest::MyClass * __thiscall SwiftDemanglerTest::MyClass::init(int label1)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassFunction() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Function
		    kind=Class
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyClass"
		    kind=Identifier, text="myMethod"
		    kind=LabelList
		      kind=Identifier, text="label1"
		      kind=Identifier, text="label2"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Structure
		              kind=Module, text="Swift"
		              kind=Identifier, text="Int"
		SwiftDemanglerTest.MyClass.myMethod(label1: Swift.Int, label2: Swift.Int) -> Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC8myMethod6label16label2S2i_SitF";
		String demangled =
			"int __thiscall SwiftDemanglerTest::MyClass::myMethod(int label1,int label2)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassGetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Getter
		    kind=Variable
		      kind=Class
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyClass"
		      kind=Identifier, text="z"
		      kind=Type
		        kind=Structure
		          kind=Module, text="Swift"
		          kind=Identifier, text="Int"
		SwiftDemanglerTest.MyClass.z.getter : Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC1zSivg";
		String demangled =
			"int __thiscall SwiftDemanglerTest::MyClass::get_z(class SwiftDemanglerTest::MyClass *)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassSetter() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Setter
		    kind=Variable
		      kind=Class
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyClass"
		      kind=Identifier, text="z"
		      kind=Type
		        kind=Structure
		          kind=Module, text="Swift"
		          kind=Identifier, text="Int"
		SwiftDemanglerTest.MyClass.z.setter : Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC1zSivs";
		String demangled = "__thiscall SwiftDemanglerTest::MyClass::set_z(int)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassModifyAccessor() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=ModifyAccessor
		    kind=Variable
		      kind=Class
		        kind=Module, text="SwiftDemanglerTest"
		        kind=Identifier, text="MyClass"
		      kind=Identifier, text="z"
		      kind=Type
		        kind=Structure
		          kind=Module, text="Swift"
		          kind=Identifier, text="Int"
		SwiftDemanglerTest.MyClass.z.modify : Swift.Int
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassC1zSivM";
		String demangled = "__thiscall SwiftDemanglerTest::MyClass::modify_z(int)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassDeallocator() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Deallocator
		    kind=Class
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyClass"
		SwiftDemanglerTest.MyClass.__deallocating_deinit
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassCfD";
		String demangled = "__thiscall SwiftDemanglerTest::MyClass::__deallocating_init(void)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testClassDestructor() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Destructor
		    kind=Class
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyClass"
		SwiftDemanglerTest.MyClass.deinit
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest7MyClassCfd";
		String demangled =
			"class SwiftDemanglerTest::MyClass * __thiscall SwiftDemanglerTest::MyClass::deinit(void)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}

	@Test
	public void testEnumFunction() throws Exception {
		/*-********************************************************************
		kind=Global
		  kind=Function
		    kind=Enum
		      kind=Module, text="SwiftDemanglerTest"
		      kind=Identifier, text="MyAssociatedEnum"
		    kind=Identifier, text="myMethod"
		    kind=LabelList
		      kind=Identifier, text="label1"
		    kind=Type
		      kind=FunctionType
		        kind=ArgumentTuple
		          kind=Type
		            kind=Tuple
		              kind=TupleElement
		                kind=Type
		                  kind=Structure
		                    kind=Module, text="Swift"
		                    kind=Identifier, text="Int"
		        kind=ReturnType
		          kind=Type
		            kind=Enum
		              kind=Module, text="SwiftDemanglerTest"
		              kind=Identifier, text="MyAssociatedEnum"
		SwiftDemanglerTest.MyAssociatedEnum.myMethod(label1: Swift.Int) -> SwiftDemanglerTest.MyAssociatedEnum
		**********************************************************************/
		String mangled = "_$s18SwiftDemanglerTest16MyAssociatedEnumO8myMethod6label1ACSi_tF";
		String demangled =
			"struct SwiftDemanglerTest::MyAssociatedEnum default SwiftDemanglerTest::MyAssociatedEnum::myMethod(int label1,struct SwiftDemanglerTest::MyAssociatedEnum,undefined)";

		if (!(demangler.demangle(mangled) instanceof DemangledFunction function)) {
			throw new AssertException("Demangled object is not a function");
		}
		assertEquals(demangled, function.toString());
	}
}
