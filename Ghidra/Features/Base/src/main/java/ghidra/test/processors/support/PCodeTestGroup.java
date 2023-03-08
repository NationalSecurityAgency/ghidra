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

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;

/**
 * <code>PCodeTestGroup</code> identifies a test group function and its corresponding
 * PCodeTestGroupControlBlock.
 */
public class PCodeTestGroup implements Comparable<PCodeTestGroup> {

	/**
	 * All test-group function names defined within the test binary must start with "main_"
	 */
	public static final String FUNCTION_NAME_PREFIX = "main_";

	public static final String IGNORED_TAG = "IGNORED";
	private static final String IGNORED_FAILED_TAG = "(" + IGNORED_TAG + ")";
	private static final String IGNORED_PASSED_TAG = "(Passed and " + IGNORED_TAG + ")";

	public final String testGroupName;
	public final Address functionEntryPtr;
//	public final int testCount; // TODO: not yet fully implemented - do not use!

	public final PCodeTestControlBlock mainTestControlBlock;
	public final PCodeTestGroupControlBlock controlBlock;

	private ArrayList<String> testFailures = new ArrayList<>();

	PCodeTestGroup(PCodeTestGroupControlBlock controlBlock) {
		this.testGroupName = controlBlock.getTestGroupName();
		this.functionEntryPtr = controlBlock.getTestGroupMainAddress();
//		this.testCount = testCount;
		this.controlBlock = controlBlock;
		this.mainTestControlBlock = controlBlock.mainTestControlBlock;
	}

	@Override
	public String toString() {
		return testGroupName + "@" + functionEntryPtr;
	}

	boolean isIgnoredTest(String testName) {
		return mainTestControlBlock.getTestResults().isIgnoredTest(testName);
	}

	void testPassed(String testName, String errFileName, int errLineNum, Program program,
			TestLogger logger) {
		if (isIgnoredTest(testName)) {
			mainTestControlBlock.resultIgnored(testGroupName, testName, true);
			String testDetail =
				getTestDetail(testName, errFileName, errLineNum, program, IGNORED_PASSED_TAG);
			testFailures.add(testDetail);
			logger.log(this, "WARNING! Ignored Test Passed: " + testDetail);
			return;
		}
		mainTestControlBlock.getTestResults().addPassResult(testGroupName, testName);
	}

	void testFailed(String testName, String errFileName, int errLineNum, boolean callOtherFailure,
			Program program, TestLogger logger) {
		String ignoreTag = "";
		if (isIgnoredTest(testName)) {
			mainTestControlBlock.resultIgnored(testGroupName, testName, false);
			ignoreTag = IGNORED_FAILED_TAG;
		}
		else if (callOtherFailure) {
			mainTestControlBlock.getTestResults().addCallOtherResult(testGroupName, testName);
		}
		else {
			mainTestControlBlock.getTestResults().addFailResult(testGroupName, testName);
		}
		String testDetail = getTestDetail(testName, errFileName, errLineNum, program, ignoreTag);
		testFailures.add(testDetail);
		logger.log(this,
			"Test Failed: " + testDetail +
				(callOtherFailure ? " (callother error)" : ""));
	}

	void severeTestFailure(String testName, String errFileName, int errLineNum, Program program,
			TestLogger logger) {
		mainTestControlBlock.getTestResults().addSevereFailResult(testGroupName, testName);
		testFailed(testName, errFileName, errLineNum, false, program, logger);
	}

	void clearFailures() {
		testFailures.clear();
	}

	private String getTestDetail(String testName, String errFileName, int errLineNum,
			Program program, String ignoreTag) {
		String testDetail = testName;
		if (testName != null) {
			Symbol symbol = SymbolUtilities.getLabelOrFunctionSymbol(program, testName,
				err -> Msg.error(this, err));
			if (symbol != null) {
				testDetail += " @ " + symbol.getAddress().toString(true);
			}
			testDetail += " (" + errFileName + ":" + errLineNum + ") " + ignoreTag;
		}
		return testDetail;
	}

	/**
	 * @return list of recorded emulation test failures
	 */
	public List<String> getTestFailures() {
		return new ArrayList<>(testFailures);
	}

	@Override
	public int hashCode() {
		return testGroupName.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof PCodeTestGroup)) {
			return false;
		}
		PCodeTestGroup other = (PCodeTestGroup) obj;
		return (controlBlock == other.controlBlock) && testGroupName.equals(other.testGroupName);
	}

	@Override
	public int compareTo(PCodeTestGroup o) {
		return testGroupName.compareTo(o.testGroupName);
	}
}
