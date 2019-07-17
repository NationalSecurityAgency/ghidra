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
package ghidra.test.processors.support;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;

/**
 * <code>PCodeTestGroupControlBlock</code> corresponds to each test group contained within 
 * a binary test file and identified by the GROUP_CONTROL_BLOCK_MAGIC 64-bit character 
 * field value at the start of the data structure.
 */
public class PCodeTestGroupControlBlock extends PCodeTestAbstractControlBlock {

	static String TEST_GROUP_NAME_SUFFIX = "_main";
	static String TEST_GROUP_FUNCTION_SUFFIX = "_Main";

	static final String GROUP_CONTROL_BLOCK_MAGIC = "aBcDefGh";

	public final PCodeTestControlBlock mainTestControlBlock;

	private String testGroupName;
	private Address testGroupMainAddr;

	/**
	 * Construct test group control block instance for the specified
	 * program.  Create GroupInfo structure data within program if requested.
	 * @param program
	 * @param groupInfoStructAddr program address where structure resides
	 * @param groupInfoStruct GroupInfo structure definition
	 * @param applyStruct create GroupInfo structure data within program if true
	 * @throws InvalidControlBlockException
	 * @throws CodeUnitInsertionException if applyStruct failed
	 */
	PCodeTestGroupControlBlock(Program program, Address groupInfoStructAddr,
			Structure groupInfoStruct, boolean applyStruct,
			PCodeTestControlBlock mainTestControlBlock)
			throws InvalidControlBlockException, CodeUnitInsertionException {
		super(program, groupInfoStructAddr, groupInfoStruct);

		this.mainTestControlBlock = mainTestControlBlock;

		readControlBlock(applyStruct);

		if (getNumberFunctions() < 1) {
			throw new InvalidControlBlockException("GroupInfo @ " + infoStructAddr.toString(true) +
				" does not define any functions: " + infoStructAddr);
		}

		testGroupName = getFunctionInfo(0).functionName;
		if (!testGroupName.endsWith(TEST_GROUP_NAME_SUFFIX)) {
			throw new InvalidControlBlockException("GroupInfo @ " + infoStructAddr.toString(true) +
				" does not define <group>_main function as first function");
		}
		testGroupName =
			testGroupName.substring(0, testGroupName.length() - TEST_GROUP_NAME_SUFFIX.length());
		testGroupMainAddr = getFunctionInfo(0).functionAddr;

	}

	public String getTestGroupName() {
		return testGroupName;
	}

	public Address getTestGroupMainAddress() {
		return testGroupMainAddr;
	}

}
