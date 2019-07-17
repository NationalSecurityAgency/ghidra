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
package ghidra.framework.main;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

public class VectorRegisterPspecTest extends AbstractGenericTest {
	private Program testProgram;

	private static final int YMM_BIT_SIZE = 256;
	private static final int XMM_BIT_SIZE = 128;
	private static final int VSX_BIT_SIZE = 128;
	private static final int SVE_BIT_SIZE = 256;
	private static final int NEON_BIT_SIZE = 128;

	/**
	 * Constructor
	 */
	public VectorRegisterPspecTest() {
		super();
	}

	@Test
	public void testPspecParsing_x64() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._X64);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] intelVectorRegisterNames = getIntelVectorRegisterNames();
		assertEquals(intelVectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < intelVectorRegisterNames.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(intelVectorRegisterNames[i], vectorRegs[i].getName());
			if (vectorRegs[i].getName().startsWith("Y")) {
				assertEquals(YMM_BIT_SIZE, vectorRegs[i].getBitLength());
			}
			else {
				assertEquals(XMM_BIT_SIZE, vectorRegs[i].getBitLength());
			}
			int[] lanes = vectorRegs[i].getLaneSizes();
			assertEquals(4, lanes.length);
			//test lane sizes: should be 1,2,4,8
			int laneSize = 1;
			for (int lane : lanes) {
				assertEquals(laneSize, lane);
				laneSize *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(3));
		}
	}

	@Test
	public void testPspecParsing_x86() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._X86);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] intelVectorRegisterNames = getIntelVectorRegisterNames();
		assertEquals(intelVectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < intelVectorRegisterNames.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(intelVectorRegisterNames[i], vectorRegs[i].getName());
			if (vectorRegs[i].getName().startsWith("Y")) {
				assertEquals(YMM_BIT_SIZE, vectorRegs[i].getBitLength());
			}
			else {
				assertEquals(XMM_BIT_SIZE, vectorRegs[i].getBitLength());
			}
			int[] lanes = vectorRegs[i].getLaneSizes();
			assertEquals(4, lanes.length);
			//test lane sizes: should be 1,2,4,8
			int laneSize = 1;
			for (int lane : lanes) {
				assertEquals(laneSize, lane);
				laneSize *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(3));
		}
	}

	@Test
	public void testPspecParsing_PPC_32() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._PPC_32);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] powerPcVectorRegisterNames = getPowerPCVectorRegisterNames();
		assertEquals(powerPcVectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < vectorRegs.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(powerPcVectorRegisterNames[i], vectorRegs[i].getName());
			assertEquals(VSX_BIT_SIZE, vectorRegs[i].getBitLength());
			int[] lanes = vectorRegs[i].getLaneSizes();
			assertEquals(3, lanes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int lane : lanes) {
				assertEquals(size, lane);
				size *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_PPC_6432() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._PPC_6432);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] powerPcVectorRegisterNames = getPowerPCVectorRegisterNames();
		assertEquals(powerPcVectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < vectorRegs.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(powerPcVectorRegisterNames[i], vectorRegs[i].getName());
			assertEquals(VSX_BIT_SIZE, vectorRegs[i].getBitLength());
			int[] lanes = vectorRegs[i].getLaneSizes();
			assertEquals(3, lanes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int lane : lanes) {
				assertEquals(size, lane);
				size *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_ARM() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._ARM);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] armVectorRegisterNames = getArmVectorRegisterNames();
		assertEquals(armVectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < vectorRegs.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(armVectorRegisterNames[i], vectorRegs[i].getName());
			assertEquals(NEON_BIT_SIZE, vectorRegs[i].getBitLength());
			int[] laneSizes = vectorRegs[i].getLaneSizes();
			assertEquals(3, laneSizes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int laneSize : laneSizes) {
				assertEquals(size, laneSize);
				size *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_AARCH64() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._AARCH64);
		testProgram = pBuilder.getProgram();
		Register[] vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] aarch64VectorRegisterNames = getAarch64VectorRegisterNames();
		assertEquals(aarch64VectorRegisterNames.length, vectorRegs.length);
		for (int i = 0; i < vectorRegs.length; i++) {
			assertTrue(vectorRegs[i].isVectorRegister());
			assertEquals(aarch64VectorRegisterNames[i], vectorRegs[i].getName());
			switch (vectorRegs[i].getName().substring(0, 1)) {
				case "z":
					assertEquals(SVE_BIT_SIZE, vectorRegs[i].getBitLength());
					break;
				case "q":
					assertEquals(NEON_BIT_SIZE, vectorRegs[i].getBitLength());
					break;
				default:
					throw new IllegalArgumentException(
						"bad vector register name: " + vectorRegs[i].getName());
			}
			int[] laneSizes = vectorRegs[i].getLaneSizes();
			assertEquals(4, laneSizes.length);
			//sizes should be 1,2,4,8
			int size = 1;
			for (int laneSize : laneSizes) {
				assertEquals(size, laneSize);
				size *= 2;
			}
			assertFalse(vectorRegs[i].isValidLaneSize(3));
		}
	}

	private String[] getPowerPCVectorRegisterNames() {
		String[] vectorRegs = new String[64];
		for (int i = 0; i < 64; i++) {
			vectorRegs[i] = "vs" + Integer.toString(i);
		}
		return vectorRegs;
	}

	private String[] getIntelVectorRegisterNames() {
		String[] vectorRegs = new String[32];
		for (int i = 0; i < 16; i++) {
			vectorRegs[i] = "YMM" + Integer.toString(i);
		}
		for (int i = 16; i < 32; i++) {
			vectorRegs[i] = "XMM" + Integer.toString(i - 16);
		}
		return vectorRegs;
	}

	private String[] getAarch64VectorRegisterNames() {
		String[] vectorRegs = new String[64];
		for (int i = 0; i < 32; i++) {
			vectorRegs[i] = "z" + Integer.toString(i);
		}
		for (int i = 0; i < 32; i++) {
			vectorRegs[i + 32] = "q" + Integer.toString(i);
		}
		return vectorRegs;
	}

	private String[] getArmVectorRegisterNames() {
		String[] vectorRegs = new String[16];
		for (int i = 0; i < 16; i++) {
			vectorRegs[i] = "q" + Integer.toString(i);
		}
		return vectorRegs;
	}

}
