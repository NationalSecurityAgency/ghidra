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
package ghidra.pcode.struct.sub;

import static org.junit.Assert.assertEquals;

import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandles.Lookup;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.pcode.exec.SleighPcodeUseropDefinition;
import ghidra.pcode.struct.StructuredSleigh;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;

public class StructuredSleighTest extends AbstractGhidraHeadlessIntegrationTest {
	private Language toy;
	private CompilerSpec cs;
	private Register r0;

	protected class TestStructuredSleigh extends StructuredSleigh {
		protected TestStructuredSleigh() {
			super(cs);
		}

		@Override
		protected Lookup getMethodLookup() {
			return MethodHandles.lookup();
		}
	}

	@Before
	public void setUp() throws Exception {
		toy = getLanguageService().getLanguage(new LanguageID(ToyProgramBuilder._TOY64_BE));
		cs = toy.getDefaultCompilerSpec();
		r0 = toy.getRegister("r0");
	}

	@Test
	public void testSimpleReturn() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop(type = "int")
			public void my_userop(@Param(type = "int", name = "param_1") Var param_1) {
				_result(param_1.muli(2));
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("__op_output = (param_1 * 0x2:4);\n", myUserop.getBody());
	}

	@Test(expected = SleighException.class)
	public void testDuplicateSymbolErr() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop(type = "int")
			public void my_userop(@Param(type = "int", name = "r0") Var r0) {
				_result(r0.muli(2));
			}
		};
		ss.generate().get("my_userop");
	}

	@Test
	public void testUseRegister() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			final Var vR0 = reg(r0, type("int"));;

			@StructuredUserop(type = "int")
			public void my_userop() {
				_result(vR0.muli(2));
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("__op_output = (r0 * 0x2:4);\n", myUserop.getBody());
	}

	@Test
	public void testLocalVarNoInit() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop(type = "int")
			public void my_userop() {
				Var myVar = local("my_var", type("int"));
				_result(myVar.muli(2));
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("""
				local my_var:4;
				__op_output = (my_var * 0x2:4);
				""", myUserop.getBody());
		// Verify the source compiles
		myUserop.programFor(new Varnode(r0.getAddress(), r0.getNumBytes()), List.of(),
			PcodeUseropLibrary.NIL);
	}

	@Test
	public void testUseropReturnTypeDefaultsVoid() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop
			public void my_userop() {
				// Don't need to do anything
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("", myUserop.getBody());
	}

	@Test
	public void testIfElseStmt() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop
			public void my_userop(@Param(name = "tmp", type = "int") Var tmp) {
				_if(lit(1, 1), () -> {
					tmp.set(1);
				})._else(() -> {
					tmp.set(2);
				});
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("""
				if 0x1:1 goto <L1>;
				tmp = 0x2:4;
				goto <L2>;
				<L1>
				tmp = 0x1:4;
				<L2>
				""", myUserop.getBody());
	}

	@Test
	public void testIfStmt() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop
			public void my_userop(@Param(name = "tmp", type = "int") Var tmp) {
				_if(lit(1, 1), () -> {
					tmp.set(1);
				});
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("""
				if (!0x1:1) goto <L1>;
				tmp = 0x1:4;
				<L1>
				""", myUserop.getBody());
	}

	@Test
	public void testForStmt() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop(type = "int")
			public void my_userop(@Param(name = "n", type = "int") Var n) {
				Var i = local("i", type("int"));
				Var sum = local("sum", type("int"));
				_for(i.set(0), i.ltiu(n), i.inc(), () -> {
					sum.addiTo(i);
				});
				_result(sum);
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("""
				local i:4;
				local sum:4;
				i = 0x0:4;
				<L2>
				if (i >= n) goto <L1>;
				sum = (sum + i);
				i = (i + 0x1:4);
				goto <L2>;
				<L1>
				__op_output = sum;
				""", myUserop.getBody());
	}

	@Test
	public void testForWithBreakStmt() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop(type = "int")
			public void my_userop(@Param(name = "n", type = "int") Var n) {
				Var i = local("i", type("int"));
				Var sum = local("sum", type("int"));
				_for(i.set(0), i.ltiu(n), i.inc(), () -> {
					sum.addiTo(i);
					_if(sum.gteiu(1000), () -> {
						_break();
					});
				});
				_result(sum);
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("""
				local i:4;
				local sum:4;
				i = 0x0:4;
				<L2>
				if (i >= n) goto <L1>;
				sum = (sum + i);
				if (sum >= 0x3e8:4) goto <L1>;
				i = (i + 0x1:4);
				goto <L2>;
				<L1>
				__op_output = sum;
				""", myUserop.getBody());
	}

	@Test
	public void testReturnStmt() throws Exception {
		StructuredSleigh ss = new TestStructuredSleigh() {
			@StructuredUserop
			public void my_userop() {
				_return(lit(0xdeadbeefL, 8));
			}
		};
		SleighPcodeUseropDefinition<Object> myUserop = ss.generate().get("my_userop");
		assertEquals("return [0xdeadbeef:8];\n", myUserop.getBody());
		// TODO: Test that the generated code compiles in a slaspec file.
		// It's rejected for injects because "return" is not valid there.
	}
}
