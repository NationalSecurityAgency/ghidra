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
package ghidra.machinelearning.functionfinding;

import static org.junit.Assert.*;

import java.util.Iterator;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.tribuo.Example;
import org.tribuo.Feature;
import org.tribuo.classification.Label;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractProgramBasedTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DataGatheringUtilsTest extends AbstractProgramBasedTest {

	private final static String BASE_ADDRESS = "0x10000";
	private final static String ADD_R0_R1_R2_ARM = "02 00 81 e0";
	private final static String SUB_R4_R5_R6_ARM = "06 40 45 e0";

	private final static String ADD_R0_R1_THUMB = "08 44";

	@Before
	public void setUp() throws Exception {
		initialize();
	}

	@Override
	protected Program getProgram() throws Exception {
		return buildProgram();
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("DataGatheringUtilsTest", ProgramBuilder._ARM);
		MemoryBlock block = builder.createMemory(".text", BASE_ADDRESS, 0x100);
		builder.setExecute(block, true);
		//undefined
		builder.setBytes(BASE_ADDRESS, "00 01 02 03", false);

		builder.setBytes("0x10004", ADD_R0_R1_R2_ARM, true);
		builder.setBytes("0x10008", SUB_R4_R5_R6_ARM, true);

		builder.setRegisterValue("TMode", "0x1000c", "0x1000f", 1);
		builder.setBytes("0x1000c", ADD_R0_R1_THUMB, true);
		builder.setBytes("0x1000e", ADD_R0_R1_THUMB, true);
		DataType intType = new IntegerDataType();
		builder.setBytes("0x10020", "00 01 02 03", false);
		builder.applyDataType("0x10020", intType);
		builder.setBytes("0x10024", "04 05 06 07", false);
		builder.applyDataType("0x10024", intType);
		builder.setBytes("0x10030", "08 09 0a 0b", false);
		builder.applyDataType("0x10030", intType);
		return builder.getProgram();
	}

	@Test
	public void testGetByteValues() {
		Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10008);
		List<Feature> test = ModelTrainingUtils.getFeatureVector(program, base, 1, 1, false);
		assertEquals(2, test.size());
		assertEquals("pbyte_0", test.get(0).getName());
		assertEquals(224.0d, test.get(0).getValue(), 0.0);
		assertEquals("ibyte_0", test.get(1).getName());
		assertEquals(6d, test.get(1).getValue(), 0.0);
	}

	@Test
	public void testGetBitValues() {
		Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10008);
		List<Feature> test = ModelTrainingUtils.getFeatureVector(program, base, 1, 1, true);
		assertEquals(18, test.size());
		assertEquals("pbyte_0", test.get(0).getName());
		assertEquals("pbit_0_7", test.get(1).getName());
		assertEquals("pbit_0_6", test.get(2).getName());
		assertEquals("pbit_0_5", test.get(3).getName());
		assertEquals("pbit_0_4", test.get(4).getName());
		assertEquals("pbit_0_3", test.get(5).getName());
		assertEquals("pbit_0_2", test.get(6).getName());
		assertEquals("pbit_0_1", test.get(7).getName());
		assertEquals("pbit_0_0", test.get(8).getName());
		assertEquals("ibyte_0", test.get(9).getName());
		assertEquals("ibit_0_7", test.get(10).getName());
		assertEquals("ibit_0_6", test.get(11).getName());
		assertEquals("ibit_0_5", test.get(12).getName());
		assertEquals("ibit_0_4", test.get(13).getName());
		assertEquals("ibit_0_3", test.get(14).getName());
		assertEquals("ibit_0_2", test.get(15).getName());
		assertEquals("ibit_0_1", test.get(16).getName());
		assertEquals("ibit_0_0", test.get(17).getName());

		//e0 06
		assertEquals(224.0d, test.get(0).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ONE, test.get(1).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ONE, test.get(2).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ONE, test.get(3).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(4).getValue(), 0.0);

		assertEquals(ModelTrainingUtils.ZERO, test.get(5).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(6).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(7).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(8).getValue(), 0.0);

		assertEquals(6d, test.get(9).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(10).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(11).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(12).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(13).getValue(), 0.0);

		assertEquals(ModelTrainingUtils.ZERO, test.get(14).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ONE, test.get(15).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ONE, test.get(16).getValue(), 0.0);
		assertEquals(ModelTrainingUtils.ZERO, test.get(17).getValue(), 0.0);
	}

	@Test
	public void testGetFollowingAddresses() throws CancelledException {
		Address one = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10004);
		Address two = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000c);
		AddressSet addrs = new AddressSet(one);
		addrs.add(two);
		AddressSet following =
			ModelTrainingUtils.getFollowingAddresses(program, addrs, TaskMonitor.DUMMY);
		assertEquals(2, following.getNumAddresses());
		assertTrue(following.contains(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10008)));
		assertTrue(following.contains(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000e)));
	}

	@Test
	public void testGetPrecedingAddresses() throws CancelledException {
		Address one = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10004);
		Address two = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000c);
		AddressSet addrs = new AddressSet(one);
		addrs.add(two);
		AddressSet following =
			ModelTrainingUtils.getPrecedingAddresses(program, addrs, TaskMonitor.DUMMY);
		assertEquals(2, following.getNumAddresses());
		assertTrue(following.contains(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10003)));
		assertTrue(following.contains(
			program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10008)));
	}

	@Test
	public void testGetDefinedData() throws CancelledException {
		AddressSet data = ModelTrainingUtils.getDefinedData(program, TaskMonitor.DUMMY);
		assertEquals(12, data.getNumAddresses());
		Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10020);
		Address end = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10027);
		assertTrue(data.contains(start, end));
		start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10030);
		end = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10033);
		assertTrue(data.contains(start, end));
	}

	@Test
	public void testGetVectorsFromAddresses() throws CancelledException {
		Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x10008);
		AddressSet testSet = new AddressSet(base);

		List<Example<Label>> testVectorList = ModelTrainingUtils.getVectorsFromAddresses(program,
			testSet, RandomForestFunctionFinderPlugin.FUNC_START, 1, 1, true, TaskMonitor.DUMMY);
		assertEquals(1, testVectorList.size());
		Example<Label> testVector = testVectorList.get(0);
		assertEquals(RandomForestFunctionFinderPlugin.FUNC_START, testVector.getOutput());
		testFeatureVector(testVector.iterator());

		testVectorList = ModelTrainingUtils.getVectorsFromAddresses(program, testSet,
			RandomForestFunctionFinderPlugin.NON_START, 1, 1, true, TaskMonitor.DUMMY);
		assertEquals(1, testVectorList.size());
		testVector = testVectorList.get(0);
		assertEquals(RandomForestFunctionFinderPlugin.NON_START, testVector.getOutput());
		testFeatureVector(testVector.iterator());
	}

	private void testFeatureVector(Iterator<Feature> iter) {
		while (iter.hasNext()) {
			Feature feature = iter.next();
			switch (feature.getName()) {
				case "pbyte_0":
					assertEquals(224d, feature.getValue(), 0.0);
					break;
				case "ibyte_0":
					assertEquals(6d, feature.getValue(), 0.0);
					break;
				case "pbit_0_7":
				case "pbit_0_6":
				case "pbit_0_5":
					assertEquals(ModelTrainingUtils.ONE, feature.getValue(), 0.0);
					break;
				case "pbit_0_4":
				case "pbit_0_3":
				case "pbit_0_2":
				case "pbit_0_1":
				case "pbit_0_0":
				case "ibit_0_7":
				case "ibit_0_6":
				case "ibit_0_5":
				case "ibit_0_4":
				case "ibit_0_3":
					assertEquals(ModelTrainingUtils.ZERO, feature.getValue(), 0.0);
					break;
				case "ibit_0_2":
				case "ibit_0_1":
					assertEquals(ModelTrainingUtils.ONE, feature.getValue(), 0.0);
					break;
				case "ibit_0_0":
					assertEquals(ModelTrainingUtils.ZERO, feature.getValue(), 0.0);
					break;
				default:
					fail("Unknown feature name: " + feature.getName());
			}
		}
	}

}
