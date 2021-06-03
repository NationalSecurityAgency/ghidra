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
package mdemangler;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.rules.TestName;

import ghidra.util.Msg;
import mdemangler.datatype.MDDataType;

/**
 * This class contains the main mechanism for performing tests for MDMangBaseTest.  The
 * mechanism is a method of sequential calls to helper methods.  MDMangBaseTest creates
 * an instance of this class (MDBaseTestConfiguration) and calls the main method.
 * Whenever there is a need for a new demangler derived from MDMang, we typically
 * desire a different output.  These outputs are all codified into MDMangBaseTest,
 * but MDBaseTestConfiguration chooses which of the demmangled results that are
 * codified in MDMangBaseTest is the one to test against.  So when we have a new
 * demangler derived from MDMang, we need a new test class derived from MDMangBaseTest
 * and a new configuration derived from MDBaseTestConfiguration.  The new test class
 * just has to allocate the new test configuration class, and the new test configuation
 * class must choose the correct codified "truth" and must override any helper test
 * methods for the test configuration class.
 */
public class MDBaseTestConfiguration {
	// Output options
	protected boolean quiet = false;
	protected boolean verboseOutput = true;

	// Internal variables
	protected String mangled;
	protected MDParsableItem demangItem;

	protected String demangled;
	protected String truth;
	protected MDMang mdm;
	protected StringBuilder outputInfo;

	public MDBaseTestConfiguration(boolean quiet) {
		this.quiet = quiet;
		mdm = new MDMang();
	}

	public void logger(StringBuilder message) {
		if (!quiet) {
			Msg.info(this, message);
		}
	}

	/**
	 * Runs through the process of creating a demangler, demangling a symbol string,
	 * testing the output, and performing other ancillary outputs and tests.
	 * @param testName TestName of the test being run.
	 * @param mangledArg Mangled string to process
	 * @param mdtruth Truth that "we" (developers of this demangler) believe is truth
	 * @param mstruth Truth that was output from one of the Microsoft tools (e.g., undname).
	 * @param ghtruth Truth that we would like to see for Ghidra version of the tool.
	 * @param ms2013truth Like mstruth, but from Visual Studio 2013 version of tool.
	 * @throws Exception if any exceptions are thrown
	 */
	public void demangleAndTest(TestName testName, String mangledArg, String mdtruth,
			String mstruth, String ghtruth, String ms2013truth) throws Exception {
		mangled = mangledArg;
		setTruth(mdtruth, mstruth, ghtruth, ms2013truth);
		outputInfo = new StringBuilder();

		if (verboseOutput) {
			outputInfo.append("\n   Test: ");
			outputInfo.append(testName.getMethodName());
			outputInfo.append(getNumberHeader(mangledArg.length()));
			outputInfo.append(getTestHeader());
		}

		// Meant to be overridden, as needed by extended classes
		doDemangleSymbol();

		doBasicTestsAndOutput();

		// Meant to be overridden, as needed by extended classes
		doExtraProcCheck();

		// Msg.info(this, outputInfo);
		logger(outputInfo);
		// Is the string mangled and is the truth unknown (truth matches input)?
		// Historically, with the Microsoft demangler (undname or dumpbin), if the output equals
		//  the input (it could also produce garbage), then it did not know how to demangle the
		//  input.  Here, "truth" represents either Microsoft's or one of my desired results, and
		//  we hold to this pattern that if we do not know how to demangle the input, we represent
		//  this as truth.equals(mangledArg).  However, if a symbol is not actually mangled, MSFT
		//  also  outputs the original (we hope that a C-language symbol going in will look
		//  exactly the same coming out).
		// So this logic of this if-else is as follows:
		//  If the symbol is recognized as mangled and the truth is equal to this mangled string
		//  (meaning that we as testers or MSFT do not know what the demangled output should look
		//  like), then we expect MDMang to also not know how to demangle it... it just so
		//  happens that we coded MDMang to return an empty string in this case.  The "else" of
		//  this is that if the symbol does not appear to be mangled (like C-language) OR we
		//  expect to be able to demangle the input (truth not equal to mangleArg), then we
		//  expect the output to be that which we desire ("truth".equals(demangled)).
		if ((truth.equals(mangledArg)) && isMangled(mangledArg)) {
			assertTrue(demangled.isEmpty());
		}
		else {
			assertEquals(truth, demangled);
		}
		if (mangledArg.startsWith(".?A")) {
			assertTrue((demangItem != null) && (demangItem instanceof MDDataType)); // Test for data type.
		}
	}

	private boolean isMangled(String s) {
		if (s.charAt(0) == '?') {
			return true;
		}
		else if (s.startsWith("__")) {
			return true;
		}
		else if ((s.charAt(0) == '_') || Character.isUpperCase(s.charAt(1))) {
			return true;
		}
		return false;
	}

	private static final String printHeaderTens =
		"0000000000111111111122222222223333333333444444444455555555556666666666777777777788888888889999999999";
	private static final String printHeaderOnes =
		"0123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789";

	protected String getNumberHeader(int length) {
		StringBuilder header = new StringBuilder();
		int remainingChars = length;
		header.append("\n         ");
		while (remainingChars > printHeaderTens.length()) {
			header.append(printHeaderTens);
			remainingChars -= printHeaderTens.length();
		}
		header.append(printHeaderTens.substring(0, remainingChars));
		remainingChars = length;
		header.append("\n         ");
		while (remainingChars > printHeaderOnes.length()) {
			header.append(printHeaderOnes);
			remainingChars -= printHeaderOnes.length();
		}
		header.append(printHeaderOnes.substring(0, remainingChars));
		return header.toString();
	}

	protected String getTestHeader() {
		StringBuilder header = new StringBuilder();
		header.append("\nMangled: ");
		header.append(mangled);
		header.append("\n  Truth: ");
		header.append(truth);
		header.append("\nSzTruth: ");
		header.append(truth.length());
		header.append("\n");
		return header.toString();
	}

	// Meant to be overridden, as needed by extended classes
	/**
	 * This method is meant to be overridden by any of the derived classes.  They get the
	 *  change to select any of the parameter inputs to set the "truth" variable for the test.
	 * These inputs could be expanded in the future as we understand the differences in the
	 *  versions of Visual Studio.
	 * Note that some of the input parameters (e.g., ghtruth and ms2013truth) could be null,
	 *  which is typical if the truth that they are seeking is found in one of the other
	 *  parameters.  So, for instance, with VS2013 testing, if ms2013truth is not null, use it,
	 *  else use the mstruth value.
	 * @param mdtruth The MDMang truth (from hands-on analysis and such).
	 * @param mstruth The Microsoft Truth (at least from VS2015).
	 * @param ghtruth The truth we would like to see for Ghidra.
	 * @param ms2013truth The Microsoft Truth (for VS2013).
	 */
	protected void setTruth(String mdtruth, String mstruth, String ghtruth, String ms2013truth) {
		truth = mdtruth;
	}

	// Meant to be overridden, as needed by extended classes
	protected void doDemangleSymbol() throws Exception {
		try {
			demangItem = mdm.demangle(mangled, true);
			demangled = demangItem.toString();
		}
		catch (MDException e) {
			demangItem = null;
			demangled = "";
		}
	}

	// Meant to be overridden, as needed by extended classes
	protected void doBasicTestsAndOutput() throws Exception {
		if (verboseOutput) {
			outputInfo.append("Remains: ");
			outputInfo.append(mdm.getNumCharsRemaining());
			outputInfo.append("\n");
			if (demangled != null) {
				outputInfo.append(" Demang: ");
				outputInfo.append(demangled);
				outputInfo.append("\n");
				outputInfo.append("  SzDem: ");
				outputInfo.append(demangled.length());
				outputInfo.append("\n");
			}
			else {
				outputInfo.append(" Demang: null\n");
				outputInfo.append("  SzDem: N/A\n");
			}
		}
	}

	protected void doExtraProcCheck() throws Exception {
		// Meant to be overridden, as needed by extended classes
	}
}
