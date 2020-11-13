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

import java.io.*;
import java.util.*;

import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;

import ghidra.test.processors.support.PCodeTestResults.TestResults;
import ghidra.util.HTMLUtilities;
import ghidra.util.Msg;
import ghidra.util.xml.GenericXMLOutputter;
import ghidra.util.xml.XmlUtilities;
import resources.ResourceManager;

public class PCodeTestCombinedTestResults {

	public static final String FILENAME = "pcode_test_results";

	private static String XML_VERSION = "1";

	// char width used when computing result column width
	private static int CHAR_WIDTH = 6;

	private File xmlFile;
	private File htmlFile;

	private Map<String, PCodeTestResults> combinedResults = new HashMap<>();

	PCodeTestCombinedTestResults(File reportsDir, boolean readExisting) throws IOException {
		this.xmlFile = new File(reportsDir, FILENAME + ".xml");
		this.htmlFile = new File(reportsDir, FILENAME + ".html");
		if (readExisting && xmlFile.exists()) {
			restoreFromXml();
		}
	}

	public PCodeTestResults getTestResults(String jUnitName, boolean create) {
		PCodeTestResults testResults = combinedResults.get(jUnitName);
		if (testResults == null && create) {
			testResults = new PCodeTestResults(jUnitName);
			combinedResults.put(jUnitName, testResults);
		}
		return testResults;
	}

	private void restoreFromXml() throws IOException {

		FileInputStream istream = new FileInputStream(xmlFile);
		BufferedInputStream bis = new BufferedInputStream(istream);
		try {
			SAXBuilder sax = XmlUtilities.createSecureSAXBuilder(false, false);
			Document doc = sax.build(bis);
			Element root = doc.getRootElement();

			if (!"PCODE_TESTS".equals(root.getName()) ||
				!XML_VERSION.equals(root.getAttributeValue("VERSION"))) {
				return;
			}

			@SuppressWarnings("unchecked")
			List<Element> elementList = root.getChildren(PCodeTestResults.TAG_NAME);
			for (Element element : elementList) {
				PCodeTestResults testResults = new PCodeTestResults(element);
				combinedResults.put(testResults.getJUnitName(), testResults);
			}
		}
		catch (org.jdom.JDOMException je) {
			throw new IOException("Invalid P-Code test results xml file: " + xmlFile, je);
		}
		finally {
			istream.close();
		}

	}

	void saveToXml() throws IOException {

		File dir = xmlFile.getParentFile();
		if (!dir.exists() && !dir.mkdir()) {
			throw new IOException("Failed to created directory: " + dir);
		}

		Element root = new Element("PCODE_TESTS");
		root.setAttribute("VERSION", XML_VERSION);

		for (String name : combinedResults.keySet()) {
			PCodeTestResults testResults = combinedResults.get(name);
			root.addContent(testResults.saveToXml());
		}

		// Store checkout data in temporary file
		File tmpFile = new File(xmlFile.getParentFile(), xmlFile.getName() + ".new");
		tmpFile.delete();
		FileOutputStream ostream = new FileOutputStream(tmpFile);
		BufferedOutputStream bos = new BufferedOutputStream(ostream);

		try {
			Document doc = new Document(root);
			XMLOutputter xmlout = new GenericXMLOutputter();
			xmlout.output(doc, bos);
		}
		finally {
			bos.close();
		}

		// Rename files
		File oldFile = null;
		if (xmlFile.exists()) {
			oldFile = new File(xmlFile.getParentFile(), xmlFile.getName() + ".bak");
			oldFile.delete();
			if (!xmlFile.renameTo(oldFile)) {
				throw new IOException("Failed to update: " + xmlFile.getAbsolutePath());
			}
		}
		if (!tmpFile.renameTo(xmlFile)) {
			if (oldFile != null) {
				oldFile.renameTo(xmlFile);
			}
			throw new IOException("Failed to update: " + xmlFile.getAbsolutePath());
		}

		Msg.info(this, "XML results file updated: " + xmlFile.getAbsolutePath());

		if (oldFile != null) {
			oldFile.delete();
		}
	}

	void copyResourceFile(String resourceName, PrintWriter w) throws IOException {
		InputStream in = ResourceManager.getResourceAsStream(resourceName);
		if (in == null) {
			throw new FileNotFoundException("Resource not found: " + resourceName);
		}
		in = new BufferedInputStream(in);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String line;
		while ((line = br.readLine()) != null) {
			w.println(line);
		}
		in.close();
	}

	private static class NamedTestColumn implements Comparable<NamedTestColumn> {
		private final String groupTestName;
		//String groupName;
		private final String testName;
		int charCount = 5; // char-count (minimum: -/-/-)

		/**
		 * 
		 * @param groupTestName {@code <group-name>.<test-name>}
		 */
		NamedTestColumn(String groupTestName) {
			this.groupTestName = groupTestName;

			int index = groupTestName.indexOf('.');
			//String groupName = "";
			String testName = groupTestName;
			if (index >= 0) {
				//groupName = groupTestName.substring(0, index);
				testName = groupTestName.substring(index + 1);
			}

			this.testName = testName;
		}

		/**
		 * @return {@code <group-name>.<test-name>}
		 */
		public String getGroupTestName() {
			return groupTestName;
		}

		/**
		 * @return {@code <test-name>}
		 */
		public String getTestName() {
			return testName;
		}

		@Override
		public int compareTo(NamedTestColumn o) {
			return testName.compareTo(o.testName);
		}

		@Override
		public int hashCode() {
			return testName.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof NamedTestColumn)) {
				return false;
			}
			NamedTestColumn other = (NamedTestColumn) obj;
			return testName.equals(other.testName);
		}

		public int getColumnWidth() {
			return (charCount + 2) * CHAR_WIDTH;
		}

		public void adjustWidth(TestResults testResults) {
			if (testResults == null) {
				return;
			}
			int count =
				computeCharCount(testResults.passCount) + computeCharCount(testResults.failCount) +
					computeCharCount(testResults.callOtherCount) + 2;
			charCount = Math.max(count, charCount);
		}

		private static int computeCharCount(int value) {
			int count = 1;
			while (value > 9) {
				++count;
				value /= 10;
			}
			return count;
		}
	}

	void saveToHTML() throws IOException {
		File dir = htmlFile.getParentFile();
		if (!dir.exists() && !dir.mkdir()) {
			throw new IOException("Failed to created directory: " + dir);
		}

		List<String> sortedJUnitTestNames = new ArrayList<>();
		Map<String, Set<NamedTestColumn>> allTestNamesMap = new HashMap<>(); // mapped by <group-name>
		Map<String, NamedTestColumn> namedTestColumnMap = new HashMap<>(); // mapped by <group-name>.<test-name> key
		for (PCodeTestResults unitTestResults : combinedResults.values()) {
			sortedJUnitTestNames.add(unitTestResults.getJUnitName());
			for (String groupTestName : unitTestResults.getGroupTestNames()) {

				int index = groupTestName.indexOf('.');
				String groupName = "";
				if (index >= 0) {
					groupName = groupTestName.substring(0, index);
				}

				Set<NamedTestColumn> set = allTestNamesMap.get(groupName);
				if (set == null) {
					set = new HashSet<>();
					allTestNamesMap.put(groupName, set);
				}

				NamedTestColumn namedTestColumn = namedTestColumnMap.get(groupTestName);
				if (namedTestColumn == null) {
					namedTestColumn = new NamedTestColumn(groupTestName);
					namedTestColumnMap.put(groupTestName, namedTestColumn);
					set.add(namedTestColumn);
				}

				namedTestColumn.adjustWidth(unitTestResults.getTestResults(groupTestName, false));
			}
		}

		String[] groupNames = allTestNamesMap.keySet().toArray(new String[allTestNamesMap.size()]);
		Arrays.sort(groupNames);

		Map<String, NamedTestColumn[]> allTestNamesByGroup = new HashMap<>();
		for (String groupName : groupNames) {
			Set<NamedTestColumn> set = allTestNamesMap.get(groupName);
			NamedTestColumn[] namedTestColumns = set.toArray(new NamedTestColumn[set.size()]);
			Arrays.sort(namedTestColumns);
			allTestNamesByGroup.put(groupName, namedTestColumns);
		}

		Collections.sort(sortedJUnitTestNames);

		// Store checkout data in temporary file
		File tmpFile = new File(xmlFile.getParentFile(), xmlFile.getName() + ".new");
		tmpFile.delete();

		PrintWriter w = new PrintWriter(tmpFile);
		try {
			copyResourceFile("pcodetest/chunk1.hinc", w);

			writeTableHeader(w, groupNames, allTestNamesByGroup);

			copyResourceFile("pcodetest/chunk2.hinc", w);

			int rownum = 1;
			for (String name : sortedJUnitTestNames) {
				PCodeTestResults testResults = combinedResults.get(name);
				writeTestSummaryRow(w, testResults, (rownum++ % 2) == 1);
			}

			copyResourceFile("pcodetest/chunk3.hinc", w);

			boolean firstRow = true;
			for (String name : sortedJUnitTestNames) {
				PCodeTestResults testResults = combinedResults.get(name);
				writeTestResultsRow(w, groupNames, allTestNamesByGroup, testResults,
					(rownum++ % 2) == 1, firstRow);
				firstRow = false;
			}

			copyResourceFile("pcodetest/chunk4.hinc", w);
		}
		finally {
			w.flush();
			w.close();
		}

		// Rename files
		File oldFile = null;
		if (htmlFile.exists()) {
			oldFile = new File(htmlFile.getParentFile(), htmlFile.getName() + ".bak");
			oldFile.delete();
			if (!htmlFile.renameTo(oldFile)) {
				throw new IOException("Failed to update: " + htmlFile.getAbsolutePath());
			}
		}
		if (!tmpFile.renameTo(htmlFile)) {
			if (oldFile != null) {
				oldFile.renameTo(htmlFile);
			}
			throw new IOException("Failed to update: " + htmlFile.getAbsolutePath());
		}

		Msg.info(this, "HTML results file updated: " + htmlFile.getAbsolutePath());

		if (oldFile != null) {
			oldFile.delete();
		}
	}

	private void writeTableHeader(PrintWriter w, String[] groupNames,
			Map<String, NamedTestColumn[]> allTestNamesByGroup) {

		int[] groupWidth = new int[groupNames.length];

		w.println("<tr>");
		for (int groupIndex = 0; groupIndex < groupNames.length; groupIndex++) {
			String groupName = groupNames[groupIndex];
			NamedTestColumn[] namedTestColumns = allTestNamesByGroup.get(groupName);
			for (NamedTestColumn namedTestColumn : namedTestColumns) {
				int columnWidth = namedTestColumn.getColumnWidth();
				w.print("<td class=\"ResultHead\" align=\"center\" valign=\"bottom\">");
				w.print("<img src=\"X\" border=0 height=1 width=" + columnWidth + "><br>");
				w.print("<div class=\"r90\">");
				w.print(HTMLUtilities.friendlyEncodeHTML(namedTestColumn.getTestName()));
				w.println("</div></td>");
				groupWidth[groupIndex] += columnWidth;
			}
		}

		w.println("</tr><tr>");

		for (int groupIndex = 0; groupIndex < groupNames.length; groupIndex++) {
			String groupName = groupNames[groupIndex];
			NamedTestColumn[] namedTestColumns = allTestNamesByGroup.get(groupName);
			w.print(
				"<td class=\"GroupHead\" valign=\"middle\" colspan=\"" + namedTestColumns.length +
					"\" style=\"max-width:" + groupWidth[groupIndex] + ";\">&nbsp;");
			if (groupName.length() != 0) {
				w.print(HTMLUtilities.friendlyEncodeHTML(groupName));
			}
			w.println("</td>");
		}

		w.println("</tr>");
	}

	private void writeResultCount(PrintWriter w, int count, String color) {
		if (count == 0) {
			w.print("<font color=\"gray\">-</font>");
		}
		else {
			w.print("<font color=\"" + color + "\">" + Integer.toString(count) + "</font>");
		}
	}

	private void writeTestSummaryRow(PrintWriter w, PCodeTestResults testResults, boolean shaded) {
		String shadeStyle = "";
		if (shaded) {
			shadeStyle = " class=\"shade\"";
		}
		w.println("<tr" + shadeStyle + ">");

		w.print(" <td class=\"TestName\"><a href=\"../logs/" + testResults.getJUnitName() +
			".log\" target=\"_log\">");
		w.print(testResults.getJUnitName());
		w.println("</a></td><td class=\"DateTime\">");

		String time = testResults.getTime();
		if (time == null) {
			time = "&nbsp;";
		}
		w.print(time);
		w.println("</td>");

		// Summary result
		if (testResults.summaryHasIngestErrors || testResults.summaryHasRelocationErrors ||
			testResults.summaryHasDisassemblyErrors) {
			// analyzed program has relocation or disassembly errors
			w.print("<td align=\"center\" class=\"ResultSummary bad\">");
			if (testResults.summaryHasIngestErrors) {
				w.print("<font color=\"red\">Ingest-Err</font><br>");
			}
			if (testResults.summaryHasRelocationErrors) {
				w.print("<font color=\"red\">Reloc-Err</font><br>");
			}
			if (testResults.summaryHasDisassemblyErrors) {
				w.print("<font color=\"red\">Dis-Err</font>");
			}
		}
		else {
			w.print("<td align=\"center\" class=\"ResultSummary " +
				getSummaryHighlightColorClass(testResults) + "\">");
			writeResultCount(w, testResults.summaryPassCount, "green");
			w.print("/");
			writeResultCount(w, testResults.summaryFailCount, "red");
			w.print("/");
			writeResultCount(w, testResults.summaryCallOtherCount, "orange");
			if (testResults.summarySevereFailures != 0) {
				w.print("<br><font color=\"red\">ERR:&nbsp;" + testResults.summarySevereFailures +
					"</font>");
			}
		}

		w.println("</td>");

		w.println("</tr>");
	}

	private String getSummaryHighlightColorClass(PCodeTestResults testResults) {
		int failCount = testResults.summaryFailCount;
		String summaryHighlight = "";
		int totalAsserts =
			testResults.summaryPassCount + failCount + testResults.summaryCallOtherCount;
		if (testResults.summarySevereFailures != 0 ||
			totalAsserts != testResults.summaryTotalAsserts) {
			summaryHighlight = "bad";
			// bump-up failure count to reflect expected number of assertions
			int diff =
				totalAsserts - (testResults.summaryPassCount + testResults.summaryCallOtherCount);
			if (diff > 0) {
				failCount = diff;
			}
		}
		else if ((testResults.summaryPassCount != 0) && (failCount == 0) &&
			(testResults.summaryCallOtherCount == 0)) {
			summaryHighlight = "good";
		}
		return summaryHighlight;
	}

	private void writeTestResultsRow(PrintWriter w, String[] groupNames,
			Map<String, NamedTestColumn[]> allTestNamesByGroup, PCodeTestResults testResults,
			boolean shaded, boolean firstRow) {

		String shadeStyle = "";
		if (shaded) {
			shadeStyle = " class=\"shade\"";
		}
		w.println("<tr" + shadeStyle + ">");

		for (String groupName : groupNames) {
			NamedTestColumn[] namedTestColumns = allTestNamesByGroup.get(groupName);
			for (NamedTestColumn namedTestColumn : namedTestColumns) {
				String testName = namedTestColumn.getTestName();
				int pass = testResults.getPassResult(groupName, testName);
				int fail = testResults.getFailResult(groupName, testName);
				int callother = testResults.getCallOtherResult(groupName, testName);
				int total = pass + fail + callother;
				int totalAsserts = testResults.getTotalAsserts(groupName, testName);

				boolean severeFailure = testResults.hadSevereFailure(groupName, testName);

				boolean highlightBad = !severeFailure && (total != 0) && (total != totalAsserts);

				w.print(
					" <td align=\"center\" class=\"Result" + (highlightBad ? " bad" : "") + "\">");
				if (firstRow) {
					w.print("<img src=\"X\" border=0 height=1 width=" +
						namedTestColumn.getColumnWidth() + "><br>");
				}
				if (severeFailure) {
					w.print("<font color=\"red\">ERR</font>");
				}
				else {
					if (total == 0) {
						if (totalAsserts == 0) {
							w.print("<font color=\"gray\">-</font>");
						}
						else {
							w.print("<font color=\"red\">x</font>");
						}
					}
					else {
						writeResultCount(w, pass, "green");
						w.print("/");
						writeResultCount(w, fail, "red");
						w.print("/");
						writeResultCount(w, callother, "orange");
						if (total != totalAsserts) {
							w.print("<br><font color=\"red\">(!=" + totalAsserts + ")</font>");
						}
					}
				}
				w.println("</td>");
			}
		}
		w.println("</tr>");
	}
}
