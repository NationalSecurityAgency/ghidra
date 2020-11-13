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
package ghidra.util.xml;

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import org.junit.Assert;
import org.xml.sax.*;

import generic.test.AbstractGenericTest;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.listing.Program;
import ghidra.util.InvalidNameException;
import ghidra.util.Msg;
import ghidra.util.exception.*;
import ghidra.xml.*;
import utilities.util.FileUtilities;

public class XmlTestHelper {

	private GhidraProject gp;
	private boolean disposeProject;
	private File tempDir;
	private List<String> xmlList = new ArrayList<>();

	public XmlTestHelper(String tmpDirPath, GhidraProject gp) throws Exception {
		createTempDir(tmpDirPath);
		this.gp = gp;
		disposeProject = false;
	}

	public XmlTestHelper(String tmpDirPath) throws Exception {
		createTempDir(tmpDirPath);
		gp = GhidraProject.createProject(tempDir.getAbsolutePath(), "xmlTempProj", true);
		disposeProject = true;
	}

	private void createTempDir(String tmpDirPath) {
		tempDir = new File(tmpDirPath, "xmlHelper");
		if (tempDir.exists()) {
			FileUtilities.deleteDir(tempDir);
		}
		tempDir.mkdirs();
	}

	public void dispose() {
		if (disposeProject) {
			gp.close();
		}
	}

	public void add(String xml) {
		xmlList.add(xml);
	}

	/**
	 * Read an XML file as a resource.
	 *
	 * @param pkg
	 *            where resource resides
	 * @param name
	 *            name of the resource that is in the given package
	 * @throws IOException thrown if there was a problem accessing the xml resource.
	 */
	public void loadXmlResource(Package pkg, String name) throws IOException {
		String pkgName = pkg.getName();
		pkgName = pkgName.replace('.', '/');

		String resourceName = "/" + pkgName + "/" + name;
		InputStream is = getClass().getResourceAsStream(resourceName);
		if (is == null) {
			throw new IOException("Could not find resource: " + resourceName);
		}
		BufferedReader br = new BufferedReader(new InputStreamReader(is));
		String line = "";
		while (line != null) {
			line = br.readLine();
			if (line != null) {
				xmlList.add(line);
			}
		}
		br.close();
	}

	public File getTempFile(String name) {
		return new File(tempDir, name);
	}

	public GhidraProject getProject() {
		return gp;
	}

	public void compareXml(File file) throws Exception {
		Msg.debug(this, "reading test file from: " + file);
		Iterator<String> it = xmlList.iterator();
		BufferedReader reader = new BufferedReader(new FileReader(file));
		try {
			String line;
			int linenum = 0;
			while ((line = reader.readLine()) != null && it.hasNext()) {
				++linenum;
				String compareLine = it.next();
				if (!compareLine.equals(line)) {
					System.out.println("XML not Equal (line:" + linenum + ")");
					System.out.println("   " + compareLine);
					System.out.println("   " + line);
				}
				Assert.assertEquals("Line " + linenum + " not equal: ", compareLine, line);
			}
			if (line != null) {
				Assert.fail("XML File contains unexpected line: " + line);
			}
		}
		finally {
			reader.close();
		}
		if (it.hasNext()) {
			Assert.fail("XML contains unexpected line: " + it.next());
		}
	}

	public boolean containsXml(String line) {
		boolean contains = xmlList.contains(line);
		return contains;
	}

	public void printExpectedLines() {
		Msg.debug(this, "XML Lines: ");
		for (String line : xmlList) {
			Msg.debug(this, line);
		}
	}

	public XmlPullParser getXmlParser(String name) throws IOException, SAXException {
		File file = new File(tempDir, name);
		file.deleteOnExit();
		FileWriter writer = new FileWriter(file);
		Iterator<String> it = xmlList.iterator();
		while (it.hasNext()) {
			String xml = it.next();
			writer.write(xml);
			writer.write('\n');
		}

		writer.close();
		XmlPullParser parser = XmlPullParserFactory.create(file, null, false);
		return parser;
	}

	/**
	 *
	 */
	public void clearXml() {
		xmlList.clear();
	}

	class MyErrorHandler implements ErrorHandler {

		/**
		 * @see org.xml.sax.ErrorHandler#error(org.xml.sax.SAXParseException)
		 */
		@Override
		public void error(SAXParseException exception) throws SAXException {
			exception.printStackTrace();
		}

		@Override
		public void fatalError(SAXParseException exception) throws SAXException {
			exception.printStackTrace();

		}

		@Override
		public void warning(SAXParseException exception) throws SAXException {
			exception.printStackTrace();
		}
	}

	public Program loadResourceProgram(String programName) throws IOException, CancelledException,
			DuplicateNameException, InvalidNameException, VersionException {
		File file = AbstractGenericTest.getTestDataFile(programName);
		if (!file.exists()) {
			throw new FileNotFoundException("Can not find test program: " + programName);
		}
		return getProject().importProgramFast(file);
	}

	public static void assertXMLFilesEquals(File expectedXMLFile, File testXMLFile)
			throws SAXException, IOException {

		XmlPullParser expectedXMLParser = XmlPullParserFactory.create(expectedXMLFile, null, false);
		XmlPullParser testXMLParser = XmlPullParserFactory.create(testXMLFile, null, false);

		assertXMLFilesEquals(expectedXMLParser, testXMLParser);
	}

	/*
	 * Compares 2 xml files and fails if there is any difference between the two.
	 *
	 * Elements must be ordered in the same order.  Attribute values are not order sensitive.
	 *
	 * Inter-node whitespace differences are ignored.
	 *
	 * DTD definitions are ignored.
	 *
	 */
	public static void assertXMLFilesEquals(XmlPullParser expectedXMLParser,
			XmlPullParser testXMLParser) {

		Deque<String> currentPath = new ArrayDeque<>();

		while (expectedXMLParser.peek() != null && testXMLParser.peek() != null) {
			XmlElement expectedElement = expectedXMLParser.next();
			XmlElement testElement = testXMLParser.next();

			if (expectedElement.isStart()) {
				currentPath.addLast(expectedElement.getName());
			}

			if (expectedElement.isStart() != testElement.isStart() ||
				expectedElement.isEnd() != testElement.isEnd()) {
				failWithInfo("Element start/stop type does not match", expectedXMLParser,
					testXMLParser, expectedElement, testElement, currentPath);
			}

			if (!expectedElement.getName().equals(testElement.getName())) {
				failWithInfo("Element names do not match", expectedXMLParser, testXMLParser,
					expectedElement, testElement, currentPath);
			}

			if (expectedElement.isStart()) {
				Map<String, String> testAttrs = testElement.getAttributes();
				for (Entry<String, String> expectedAttr : expectedElement.getAttributes()
						.entrySet()) {
					if (!testAttrs.containsKey(expectedAttr.getKey())) {
						failWithInfo("Attribute " + expectedAttr.getKey() + " missing",
							expectedXMLParser, testXMLParser, expectedElement, testElement,
							currentPath);
					}
					String testAttrVal = testAttrs.get(expectedAttr.getKey());
					if (!expectedAttr.getValue().equals(testAttrVal)) {
						failWithInfo("Attribute " + expectedAttr.getKey() + " values do not match",
							expectedXMLParser, testXMLParser, expectedElement, testElement,
							currentPath);
					}
					testAttrs.remove(expectedAttr.getKey());
				}
				if (!testAttrs.isEmpty()) {
					failWithInfo("Unexpected attributes found: " + testAttrs.keySet().toString(),
						expectedXMLParser, testXMLParser, expectedElement, testElement,
						currentPath);
				}
			}

			if (expectedElement.isEnd()) {
				String expectedContent = expectedElement.getText().trim();
				String testContent = testElement.getText().trim();
				if (!expectedContent.equals(testContent)) {
					failWithInfo(
						"Text content does not match: /" + expectedContent + "/ vs /" +
							testContent + "/",
						expectedXMLParser, testXMLParser, expectedElement, testElement,
						currentPath);
				}
				currentPath.removeLast();
			}
		}

	}

	static String join(Collection<String> coll, String sep) {
		StringBuilder sb = new StringBuilder();
		for (String s : coll) {
			if (sb.length() > 0) {
				sb.append(sep);
			}
			sb.append(s);
		}
		return sb.toString();
	}

	static void failWithInfo(String msg, XmlPullParser parser1, XmlPullParser parser2,
			XmlElement element1, XmlElement element2, Collection<String> currentPath) {

		Assert.fail("XML compare FAILED between\n" + parser1.getName() + ":" +
			parser1.getLineNumber() + " and " + parser2.getName() + ":" + parser2.getLineNumber() +
			"\n at path " + join(currentPath, "/") + ":\n" + msg + "\nElement 1: " +
			element1.toString() + "\nElement 2: " + element2.toString());
	}

}
