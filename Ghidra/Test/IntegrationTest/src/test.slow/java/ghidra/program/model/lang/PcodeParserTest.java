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

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.UniqueLayout;
import ghidra.app.plugin.processors.sleigh.template.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.sleigh.grammar.Location;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class PcodeParserTest extends AbstractGhidraHeadlessIntegrationTest {

	public boolean testVarnode(VarnodeTpl vn, String spaceName, long offset, int size) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.SPACEID) {
			return false;
		}
		if (!vn.getSpace().getSpaceId().getName().equals(spaceName)) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.REAL) {
			return false;
		}
		if (vn.getOffset().getReal() != offset) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.REAL) {
			return false;
		}
		if (vn.getSize().getReal() != size) {
			return false;
		}
		return true;
	}

	public boolean testInstNextConstant(VarnodeTpl vn, int size) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.SPACEID) {
			return false;
		}
		if (!vn.getSpace().getSpaceId().getName().equals(SpaceNames.CONSTANT_SPACE_NAME)) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.J_NEXT) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.REAL) {
			return false;
		}
		if (vn.getSize().getReal() != size) {
			return false;
		}
		return true;
	}

	public boolean testInstNext(VarnodeTpl vn) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.J_CURSPACE) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.J_NEXT) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.J_CURSPACE_SIZE) {
			return false;
		}
		return true;
	}

	public boolean testRelative(VarnodeTpl vn, int labelid, int size) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.SPACEID) {
			return false;
		}
		if (!vn.getSpace().getSpaceId().getName().equals(SpaceNames.CONSTANT_SPACE_NAME)) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.J_RELATIVE) {
			return false;
		}
		if (vn.getOffset().getReal() != labelid) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.REAL) {
			return false;
		}
		if (vn.getSize().getReal() != size) {
			return false;
		}
		return true;
	}

	public boolean testParameter(VarnodeTpl vn, int paramnum) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.HANDLE) {
			return false;
		}
		if (vn.getSpace().getHandleIndex() != paramnum) {
			return false;
		}
		if (vn.getSpace().getSelect() != ConstTpl.V_SPACE) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.HANDLE) {
			return false;
		}
		if (vn.getOffset().getHandleIndex() != paramnum) {
			return false;
		}
		if (vn.getOffset().getSelect() != ConstTpl.V_OFFSET) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.HANDLE) {
			return false;
		}
		if (vn.getSize().getHandleIndex() != paramnum) {
			return false;
		}
		if (vn.getSize().getSelect() != ConstTpl.V_SIZE) {
			return false;
		}
		return true;
	}

	public boolean testVarnodeHandleSize(VarnodeTpl vn, String spaceName, long offset,
			int paramnum) {
		assertNotNull(vn);
		if (vn.getSpace().getType() != ConstTpl.SPACEID) {
			return false;
		}
		if (!vn.getSpace().getSpaceId().getName().equals(spaceName)) {
			return false;
		}
		if (vn.getOffset().getType() != ConstTpl.REAL) {
			return false;
		}
		if (vn.getOffset().getReal() != offset) {
			return false;
		}
		if (vn.getSize().getType() != ConstTpl.HANDLE) {
			return false;
		}
		if (vn.getSize().getHandleIndex() != paramnum) {
			return false;
		}
		if (vn.getSize().getSelect() != ConstTpl.V_SIZE) {
			return false;
		}
		return true;
	}

	@Test
	public void testCompilePcode() throws Exception {

		SleighLanguage lang = (SleighLanguage) getSLEIGH_X86_LANGUAGE();

		long uniqueBase = UniqueLayout.INJECT.getOffset(lang);

		String pcodeStatements = "tmp:1 = inst_next;\n" + "if (AX == 0) goto inst_next;\n" +
			"call [ECX];\n" + "if (BX != 1) goto <lab>;\n" + "CX = 0;\n" + "<lab>\n" +
			"BX = CX << 2;\n" + "in1 = in2 + 7;";

		PcodeParser parser = new PcodeParser(lang, uniqueBase);
		Location loc = new Location("pcodetest", 5);
		parser.addOperand(loc, "in1", 0);
		parser.addOperand(loc, "in2", 1);
		ConstructTpl template = parser.compilePcode(pcodeStatements, "test", 200);
		assertNull(template.getResult());
		assertEquals(template.getNumLabels(), 1);
		OpTpl[] vec = template.getOpVec();
		assertEquals(vec.length, 10);

		assertEquals(vec[0].getOpcode(), PcodeOp.COPY);
		assertTrue(testVarnode(vec[0].getOutput(), SpaceNames.UNIQUE_SPACE_NAME, uniqueBase, 1));
		assertEquals(vec[0].getInput().length, 1);
		assertTrue(testInstNextConstant(vec[0].getInput()[0], 1));

		assertEquals(vec[1].getOpcode(), PcodeOp.INT_EQUAL);
		assertTrue(
			testVarnode(vec[1].getOutput(), SpaceNames.UNIQUE_SPACE_NAME, uniqueBase + 0x80, 1));
		assertEquals(vec[1].getInput().length, 2);
		assertTrue(testVarnode(vec[1].getInput()[0], "register", 0, 2));
		assertTrue(testVarnode(vec[1].getInput()[1], SpaceNames.CONSTANT_SPACE_NAME, 0, 2));

		assertEquals(vec[2].getOpcode(), PcodeOp.CBRANCH);
		assertNull(vec[2].getOutput());
		assertEquals(vec[2].getInput().length, 2);
		assertTrue(testInstNext(vec[2].getInput()[0]));
		assertTrue(
			testVarnode(vec[2].getInput()[1], SpaceNames.UNIQUE_SPACE_NAME, uniqueBase + 0x80, 1));

		assertEquals(vec[3].getOpcode(), PcodeOp.CALLIND);
		assertNull(vec[3].getOutput());
		assertEquals(vec[3].getInput().length, 1);
		assertTrue(testVarnode(vec[3].getInput()[0], "register", 4, 4));

		assertEquals(vec[4].getOpcode(), PcodeOp.INT_NOTEQUAL);
		assertTrue(
			testVarnode(vec[4].getOutput(), SpaceNames.UNIQUE_SPACE_NAME, uniqueBase + 0x100, 1));
		assertEquals(vec[4].getInput().length, 2);
		assertTrue(testVarnode(vec[4].getInput()[0], "register", 0xc, 2));
		assertTrue(testVarnode(vec[4].getInput()[1], SpaceNames.CONSTANT_SPACE_NAME, 1, 2));

		assertEquals(vec[5].getOpcode(), PcodeOp.CBRANCH);
		assertNull(vec[5].getOutput());
		assertEquals(vec[5].getInput().length, 2);
		assertTrue(testRelative(vec[5].getInput()[0], 0, 4));
		assertTrue(
			testVarnode(vec[5].getInput()[1], SpaceNames.UNIQUE_SPACE_NAME, uniqueBase + 0x100, 1));

		assertEquals(vec[6].getOpcode(), PcodeOp.COPY);
		assertTrue(testVarnode(vec[6].getOutput(), "register", 4, 2));
		assertEquals(vec[6].getInput().length, 1);
		assertTrue(testVarnode(vec[6].getInput()[0], SpaceNames.CONSTANT_SPACE_NAME, 0, 2));

		assertEquals(vec[7].getOpcode(), PcodeOp.PTRADD);		// label
		assertNull(vec[7].getOutput());
		assertEquals(vec[7].getInput().length, 1);
		assertTrue(testVarnode(vec[7].getInput()[0], SpaceNames.CONSTANT_SPACE_NAME, 0, 4));

		assertEquals(vec[8].getOpcode(), PcodeOp.INT_LEFT);
		assertTrue(testVarnode(vec[8].getOutput(), "register", 0xc, 2));
		assertEquals(vec[8].getInput().length, 2);
		assertTrue(testVarnode(vec[8].getInput()[0], "register", 0x4, 2));
		assertTrue(testVarnode(vec[8].getInput()[1], SpaceNames.CONSTANT_SPACE_NAME, 2, 4));

		assertEquals(vec[9].getOpcode(), PcodeOp.INT_ADD);
		assertTrue(testParameter(vec[9].getOutput(), 0));
		assertEquals(vec[9].getInput().length, 2);
		assertTrue(testParameter(vec[9].getInput()[0], 1));
		assertTrue(
			testVarnodeHandleSize(vec[9].getInput()[1], SpaceNames.CONSTANT_SPACE_NAME, 7, 0));
	}
}
