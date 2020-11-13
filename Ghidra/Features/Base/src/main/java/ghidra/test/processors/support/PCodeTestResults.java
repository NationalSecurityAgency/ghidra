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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import org.jdom.Attribute;
import org.jdom.Element;

public class PCodeTestResults {

	private String jUnitName;

	boolean summaryHasIngestErrors;
	boolean summaryHasRelocationErrors;
	boolean summaryHasDisassemblyErrors;

	int summaryTotalAsserts;
	int summaryPassCount;
	int summaryFailCount;
	int summaryCallOtherCount;
	int summarySevereFailures;

	long time;

	// map keys formed with "<groupName>.<testName>" string
	private Map<String, TestResults> results = new HashMap<>();

	PCodeTestResults(String jUnitName) {
		this.jUnitName = jUnitName;
		time = System.currentTimeMillis();
	}

	public String getJUnitName() {
		return jUnitName;
	}

	private static DateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy HH:mm");

	public String getTime() {
		if (time == 0) {
			return null;
		}
		Date d = new Date(time);
		return dateFormat.format(d);
	}

	public int getNumberOfTests() {
		return results.size();
	}

	/**
	 * @return collection of group/testNames in the form {@code "<groupName>.<testName>"}
	 */
	public Collection<String> getGroupTestNames() {
		return results.keySet();
	}

	/**
	 * Get groupName.testName combined into single string
	 * @param groupName
	 * @param testName
	 * @return
	 */
	private String getGroupTestName(String groupName, String testName) {
		if (testName.endsWith(PCodeTestGroupControlBlock.TEST_GROUP_FUNCTION_SUFFIX)) {
			testName = testName.substring(0,
				testName.length() - PCodeTestGroupControlBlock.TEST_GROUP_FUNCTION_SUFFIX.length());
		}
		// Exclude any trailing digits from groupName which may have been appended to filename
		return groupName.replaceAll("\\d*$", "") + "." + testName;
	}

	/**
	 * Get results entry keyed by "<groupName>.<testName>"
	 * @param groupTestName
	 * @param create
	 * @return
	 */
	TestResults getTestResults(String groupTestName, boolean create) {
		TestResults testResults = results.get(groupTestName);
		if (testResults == null && create) {
			testResults = new TestResults();
			results.put(groupTestName, testResults);
		}
		return testResults;
	}

	void declareTest(String groupName, String testName, int totalAsserts) {
		String groupTestName = getGroupTestName(groupName, testName);
		getTestResults(groupTestName, true).totalAsserts = totalAsserts;
		summaryTotalAsserts += totalAsserts;
	}

	public int getTotalAsserts(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		TestResults testResults = getTestResults(groupTestName, false);
		if (testResults != null) {
			return testResults.totalAsserts;
		}
		return 0;
	}

	void addPassResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		getTestResults(groupTestName, true).passCount++;
		++summaryPassCount;
	}

	public int getPassResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		TestResults testResults = getTestResults(groupTestName, false);
		if (testResults != null) {
			return testResults.passCount;
		}
		return 0;
	}

	void addFailResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		getTestResults(groupTestName, true).failCount++;
		summaryFailCount++;
	}

	public int getFailResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		TestResults testResults = getTestResults(groupTestName, false);
		if (testResults != null) {
			return testResults.failCount;
		}
		return 0;
	}

	void addSevereFailResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		getTestResults(groupTestName, true).severeFailure = true;
		summarySevereFailures++;
	}

	public boolean hadSevereFailure(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		TestResults testResults = getTestResults(groupTestName, false);
		if (testResults != null) {
			return testResults.severeFailure;
		}
		return false;
	}

	void addCallOtherResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		getTestResults(groupTestName, true).callOtherCount++;
		summaryCallOtherCount++;
	}

	public int getCallOtherResult(String groupName, String testName) {
		String groupTestName = getGroupTestName(groupName, testName);
		TestResults testResults = getTestResults(groupTestName, false);
		if (testResults != null) {
			return testResults.callOtherCount;
		}
		return 0;
	}

	void clear() {
		results.clear();
		summaryHasIngestErrors = false;
		summaryHasRelocationErrors = false;
		summaryHasDisassemblyErrors = false;
		summaryTotalAsserts = 0;
		summaryPassCount = 0;
		summaryFailCount = 0;
		summaryCallOtherCount = 0;
		summarySevereFailures = 0;
		time = System.currentTimeMillis();
	}

	private static String XML_VERSION = "1";

	public static String TAG_NAME = "PCodeTestResults";

	public PCodeTestResults(Element root) {

		if (!TAG_NAME.equals(root.getName())) {
			throw new IllegalArgumentException("Unsupported root element: " + root.getName());
		}
		String ver = root.getAttributeValue("VERSION");
		if (!XML_VERSION.equals(ver)) {
			throw new IllegalArgumentException(
				"Unsupported XML format version " + ver + ", required format is " + XML_VERSION);
		}

		jUnitName = root.getAttributeValue("JUNIT");

		time = 0;
		String timeStr = root.getAttributeValue("TIME");
		if (timeStr != null) {
			try {
				time = Long.parseLong(timeStr);
			}
			catch (NumberFormatException e) {
				// ignore
			}
		}

		summaryHasIngestErrors = getAttributeValue(root, "INGEST_ERR", false);
		summaryHasRelocationErrors = getAttributeValue(root, "RELOC_ERR", false);
		summaryHasDisassemblyErrors = getAttributeValue(root, "DIS_ERR", false);

		@SuppressWarnings("unchecked")
		List<Element> elementList = root.getChildren("TestResults");
		for (Element element : elementList) {

			String testName = element.getAttributeValue("NAME");
			if (testName == null) {
				throw new IllegalArgumentException("Invalid TestResults element in XML");
			}
			TestResults testResults = new TestResults();
			testResults.totalAsserts = getAttributeValue(element, "TOTAL_ASSERTS", 0);
			testResults.passCount = getAttributeValue(element, "PASS", 0);
			testResults.failCount = getAttributeValue(element, "FAIL", 0);
			testResults.callOtherCount = getAttributeValue(element, "CALLOTHER", 0);
			testResults.severeFailure = getAttributeValue(element, "SEVERE_FAILURE", false);

			summaryTotalAsserts += testResults.totalAsserts;
			summaryPassCount += testResults.passCount;
			summaryFailCount += testResults.failCount;
			summaryCallOtherCount += testResults.callOtherCount;
			if (testResults.severeFailure) {
				++summarySevereFailures;
			}

			results.put(testName, testResults);
		}
	}

	int getAttributeValue(Element element, String attrName, int defaultValue) {
		String val = element.getAttributeValue(attrName);
		if (val == null) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(val);
		}
		catch (NumberFormatException e) {
			return 0;
		}
	}

	boolean getAttributeValue(Element element, String attrName, boolean defaultValue) {
		String val = element.getAttributeValue(attrName);
		if (val == null) {
			return defaultValue;
		}
		try {
			return Boolean.valueOf(val);
		}
		catch (NumberFormatException e) {
			return false;
		}
	}

	Element saveToXml() {

		Element root = new Element("PCodeTestResults");
		root.setAttribute(new Attribute("VERSION", XML_VERSION));
		root.setAttribute(new Attribute("JUNIT", jUnitName));
		if (time != 0) {
			root.setAttribute(new Attribute("TIME", Long.toString(time)));
		}

		if (summaryHasIngestErrors) {
			root.setAttribute(new Attribute("INGEST_ERR", "TRUE"));
		}

		if (summaryHasRelocationErrors) {
			root.setAttribute(new Attribute("RELOC_ERR", "TRUE"));
		}

		if (summaryHasDisassemblyErrors) {
			root.setAttribute(new Attribute("DIS_ERR", "TRUE"));
		}

		ArrayList<String> testNames = new ArrayList<>(results.keySet());
		Collections.sort(testNames);

		for (String testName : testNames) {
			TestResults testResults = results.get(testName);
			Element element = new Element("TestResults");
			element.setAttribute(new Attribute("NAME", testName));
			element.setAttribute(
				new Attribute("TOTAL_ASSERTS", Integer.toString(testResults.totalAsserts)));
			element.setAttribute(new Attribute("PASS", Integer.toString(testResults.passCount)));
			element.setAttribute(new Attribute("FAIL", Integer.toString(testResults.failCount)));
			element.setAttribute(
				new Attribute("CALLOTHER", Integer.toString(testResults.callOtherCount)));
			if (testResults.severeFailure) {
				element.setAttribute(new Attribute("SEVERE_FAILURE", "TRUE"));
			}
			root.addContent(element);
		}
		return root;
	}

	static class TestResults {
		int totalAsserts;
		int passCount;
		int failCount;
		int callOtherCount;

		boolean severeFailure = false;

		@Override
		public String toString() {
			// TODO Auto-generated method stub
			return "{" + passCount + "/" + failCount + "/" + callOtherCount + "(" + totalAsserts +
				")}";
		}
	}
}
