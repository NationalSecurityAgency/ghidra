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

import java.util.List;

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
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] intelVectorRegisterNames = getIntelVectorRegisterNames();
		assertEquals(intelVectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < intelVectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorRegs.get(i).isVectorRegister());
			assertEquals(intelVectorRegisterNames[i], vectorReg.getName());
			if (vectorReg.getName().startsWith("Y")) {
				assertEquals(YMM_BIT_SIZE, vectorReg.getBitLength());
			}
			else {
				assertEquals(XMM_BIT_SIZE, vectorReg.getBitLength());
			}
			int[] lanes = vectorReg.getLaneSizes();
			assertEquals(4, lanes.length);
			//test lane sizes: should be 1,2,4,8
			int laneSize = 1;
			for (int lane : lanes) {
				assertEquals(laneSize, lane);
				laneSize *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(3));
		}
	}

	@Test
	public void testPspecParsing_x86() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._X86);
		testProgram = pBuilder.getProgram();
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] intelVectorRegisterNames = getIntelVectorRegisterNames();
		assertEquals(intelVectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < intelVectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorReg.isVectorRegister());
			assertEquals(intelVectorRegisterNames[i], vectorReg.getName());
			if (vectorReg.getName().startsWith("Y")) {
				assertEquals(YMM_BIT_SIZE, vectorReg.getBitLength());
			}
			else {
				assertEquals(XMM_BIT_SIZE, vectorReg.getBitLength());
			}
			int[] lanes = vectorReg.getLaneSizes();
			assertEquals(4, lanes.length);
			//test lane sizes: should be 1,2,4,8
			int laneSize = 1;
			for (int lane : lanes) {
				assertEquals(laneSize, lane);
				laneSize *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(3));
		}
	}

	@Test
	public void testPspecParsing_PPC_32() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._PPC_32);
		testProgram = pBuilder.getProgram();
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] powerPcVectorRegisterNames = getPowerPCVectorRegisterNames();
		assertEquals(powerPcVectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < powerPcVectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorReg.isVectorRegister());
			assertEquals(powerPcVectorRegisterNames[i], vectorReg.getName());
			assertEquals(VSX_BIT_SIZE, vectorReg.getBitLength());
			int[] lanes = vectorReg.getLaneSizes();
			assertEquals(3, lanes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int lane : lanes) {
				assertEquals(size, lane);
				size *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_PPC_6432() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._PPC_6432);
		testProgram = pBuilder.getProgram();
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] powerPcVectorRegisterNames = getPowerPCVectorRegisterNames();
		assertEquals(powerPcVectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < powerPcVectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorReg.isVectorRegister());
			assertEquals(powerPcVectorRegisterNames[i], vectorReg.getName());
			assertEquals(VSX_BIT_SIZE, vectorReg.getBitLength());
			int[] lanes = vectorReg.getLaneSizes();
			assertEquals(3, lanes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int lane : lanes) {
				assertEquals(size, lane);
				size *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_ARM() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._ARM);
		testProgram = pBuilder.getProgram();
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] armVectorRegisterNames = getArmVectorRegisterNames();
		assertEquals(armVectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < armVectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorReg.isVectorRegister());
			assertEquals(armVectorRegisterNames[i], vectorReg.getName());
			assertEquals(NEON_BIT_SIZE, vectorReg.getBitLength());
			int[] laneSizes = vectorReg.getLaneSizes();
			assertEquals(3, laneSizes.length);
			//lane sizes should be 1, 2, 4
			int size = 1;
			for (int laneSize : laneSizes) {
				assertEquals(size, laneSize);
				size *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(5));
		}
	}

	@Test
	public void testPspecParsing_AARCH64() throws Exception {
		ProgramBuilder pBuilder = new ProgramBuilder("test", ProgramBuilder._AARCH64);
		testProgram = pBuilder.getProgram();
		List<Register> vectorRegs = testProgram.getLanguage().getSortedVectorRegisters();
		String[] aarch64VectorRegisterNames = getAarch64VectorRegisterNames();
		assertEquals(aarch64VectorRegisterNames.length, vectorRegs.size());
		for (int i = 0; i < aarch64VectorRegisterNames.length; i++) {
			Register vectorReg = vectorRegs.get(i);
			assertTrue(vectorReg.isVectorRegister());
			assertEquals(aarch64VectorRegisterNames[i], vectorReg.getName());
			switch (vectorReg.getName().substring(0, 1)) {
				case "z":
					assertEquals(SVE_BIT_SIZE, vectorReg.getBitLength());
					break;
				case "q":
					assertEquals(NEON_BIT_SIZE, vectorReg.getBitLength());
					break;
				default:
					throw new IllegalArgumentException(
						"bad vector register name: " + vectorReg.getName());
			}
			int[] laneSizes = vectorReg.getLaneSizes();
			assertEquals(4, laneSizes.length);
			//sizes should be 1,2,4,8
			int size = 1;
			for (int laneSize : laneSizes) {
				assertEquals(size, laneSize);
				size *= 2;
			}
			assertFalse(vectorReg.isValidLaneSize(3));
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
