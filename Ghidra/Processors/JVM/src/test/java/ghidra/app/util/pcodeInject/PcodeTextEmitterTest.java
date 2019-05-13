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
package ghidra.app.util.pcodeInject;

import static org.junit.Assert.*;

import org.junit.Test;

public class PcodeTextEmitterTest {

	@Test
	public void testEmitPushType1Value() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitPushCat1Value(pCode, "x");
		assertTrue(pCode.toString().equals("SP = SP - 4;\n*:4 SP = x;\n"));
	}

	@Test
	public void testEmitPushType2Value() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitPushCat2Value(pCode, "x");
		assertTrue(pCode.toString().equals("SP = SP - 8;\n*:8 SP = x;\n"));
	}

	@Test
	public void testEmitPopType1Value() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitPopCat1Value(pCode, "x");
		assertTrue(pCode.toString().equals("x:4 = *:4 SP;\nSP = SP + 4;\n"));
	}

	@Test
	public void testEmitPopType2Value() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitPopCat2Value(pCode, "x");
		assertTrue(pCode.toString().equals("x:8 = *:8 SP;\nSP = SP + 8;\n"));
	}

	@Test
	public void testEmitVarnodeBytesFromPcodeOpCall() {
		StringBuilder pCode = new StringBuilder();

		//test no args
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 4, "PCODEOP");
		assertTrue(pCode.toString().equals("LHS:4 = PCODEOP();\n"));

		//one arg
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 4, "PCODEOP", "ARG1");
		assertTrue(pCode.toString().equals("LHS:4 = PCODEOP(ARG1);\n"));

		//two args
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 4, "PCODEOP", "ARG1",
			"ARG2");
		assertTrue(pCode.toString().equals("LHS:4 = PCODEOP(ARG1,ARG2);\n"));

		//test no args
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 8, "PCODEOP");
		assertTrue(pCode.toString().equals("LHS:8 = PCODEOP();\n"));

		//one arg
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 8, "PCODEOP", "ARG1");
		assertTrue(pCode.toString().equals("LHS:8 = PCODEOP(ARG1);\n"));

		//two args
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromPcodeOpCall(pCode, "LHS", 8, "PCODEOP", "ARG1",
			"ARG2");
		assertTrue(pCode.toString().equals("LHS:8 = PCODEOP(ARG1,ARG2);\n"));
	}

	@Test
	public void testEmitVoidPcodeOpCall() {
		StringBuilder pCode = new StringBuilder();

		//test no args
		PcodeTextEmitter.emitVoidPcodeOpCall(pCode, "PCODEOP");
		assertTrue(pCode.toString().equals("PCODEOP();\n"));

		//one arg
		pCode = new StringBuilder();
		PcodeTextEmitter.emitVoidPcodeOpCall(pCode, "PCODEOP", "ARG1");
		assertTrue(pCode.toString().equals("PCODEOP(ARG1);\n"));

		//two args
		pCode = new StringBuilder();
		PcodeTextEmitter.emitVoidPcodeOpCall(pCode, "PCODEOP", "ARG1", "ARG2");
		assertTrue(pCode.toString().equals("PCODEOP(ARG1,ARG2);\n"));
	}

	@Test
	public void testEmitAssignRegisterFromPcodeOpCall() {
		//void call
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignRegisterFromPcodeOpCall(pCode, "REG", "TEST");
		assertTrue(pCode.toString().equals("REG = TEST();\n"));

		//one-param call
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignRegisterFromPcodeOpCall(pCode, "REG", "TEST", "ARG1");
		assertTrue(pCode.toString().equals("REG = TEST(ARG1);\n"));

		//two-param call
		pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignRegisterFromPcodeOpCall(pCode, "REG", "TEST", "ARG1", "ARG2");
		assertTrue(pCode.toString().equals("REG = TEST(ARG1,ARG2);\n"));
	}

	@Test
	public void testEmitAssignConstantToRegister() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignConstantToRegister(pCode, "REGISTER", 0);
		assertTrue(pCode.toString().equals("REGISTER = 0x0;\n"));
	}

	@Test
	public void testEmitLabelDef() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitLabelDefinition(pCode, "LABEL");
		assertEquals("bad label definition emitted", "<LABEL>\n", pCode.toString());
	}

	@Test
	public void testEmitIndirectCall() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitIndirectCall(pCode, "call_target");
		assertEquals("call [call_target];\n", pCode.toString());
	}

	@Test
	public void testEmitWriteToMemory() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitWriteToMemory(pCode, "ram", 4, "offset", "test");
		assertEquals("*[ram]:4 offset = test;\n", pCode.toString());
	}

	@Test
	public void testEmitSignExtension() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitSignExtension(pCode, "dest", 4, "src");
		assertEquals("dest:4 = sext(src);\n", pCode.toString());
	}

	@Test
	public void testEmitZeroExtension() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitZeroExtension(pCode, "dest", 4, "src");
		assertEquals("dest:4 = zext(src);\n", pCode.toString());
	}

	@Test
	public void testEmitTruncate() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitTruncate(pCode, "dest", 4, "src");
		assertEquals("dest = src:4;\n", pCode.toString());
	}

	@Test
	public void testAssignVarnodeFromDereference() {
		StringBuilder pCode = new StringBuilder();
		PcodeTextEmitter.emitAssignVarnodeFromDereference(pCode, "dest", 4, "src");
		assertEquals("dest:4 = *:4 src;\n", pCode.toString());
	}

}
