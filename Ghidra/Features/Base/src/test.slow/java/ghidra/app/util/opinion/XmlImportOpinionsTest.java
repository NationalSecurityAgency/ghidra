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
package ghidra.app.util.opinion;

import static org.junit.Assert.*;

import java.io.*;
import java.util.Collection;

import org.junit.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.program.model.lang.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import utilities.util.FileUtilities;

public class XmlImportOpinionsTest extends AbstractGhidraHeadlessIntegrationTest {

	private XmlLoader loader;

	@Before
	public void setUp() throws Exception {
		loader = new XmlLoader();
	}

	@After
	public void tearDown() throws Exception {
		File f = new File(getTestDirectoryPath(), "test.xml");
		f.delete();
	}

	@Test
	public void testXmlFromIDA1() throws Exception {

		try (ByteProvider byteProvider = getByteProvider("TEST1",
			"<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\">" +
				"<INFO_SOURCE USER=\"user\" TOOL=\"IDA-PRO\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" />" +
				"<PROCESSOR NAME=\"FOO\" ADDRESS_MODEL=\"32-bit\" />" +
				"<COMPILER NAME=\"GNU C++\"/> </PROGRAM>")) {

			// list limited to all little-endian languages
			checkValidXMLLoadSpec(byteProvider, loader.findSupportedLoadSpecs(byteProvider),
				"TEST1", null, null, null, "8051:BE:16:default", "6502:LE:16:default");
		}
	}

	@Test
	public void testXmlFromIDA2() throws Exception {

		try (ByteProvider byteProvider = getByteProvider("TEST2",
			"<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\">" +
				"<INFO_SOURCE USER=\"user\" TOOL=\"IDA-PRO\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" />" +
				"<PROCESSOR NAME=\"FOO\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" />" +
				"<COMPILER NAME=\"GNU C++\"/> </PROGRAM>")) {

			// list includes all languages
			checkValidXMLLoadSpec(byteProvider, loader.findSupportedLoadSpecs(byteProvider),
				"TEST2", Endian.LITTLE, null, null, "6502:LE:16:default");
		}
	}

	@Test
	public void testXmlFromIDA3() throws Exception {

		try (ByteProvider byteProvider = getByteProvider("TEST3",
			"<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\">" +
				"<INFO_SOURCE USER=\"user\" TOOL=\"Ida-ProXYZ\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" />" +
				"<PROCESSOR NAME=\"METAPC\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" />" +
				"<COMPILER NAME=\"GNU C++\"/> </PROGRAM>")) {

			// list includes all languages
			checkValidXMLLoadSpec(byteProvider, loader.findSupportedLoadSpecs(byteProvider),
				"TEST3", Endian.LITTLE, "x86", null, "x86:LE:32:default");
		}
	}

	@Test
	public void testXmlFromIDA4() throws Exception {

		try (ByteProvider byteProvider = getByteProvider("TEST4",
			"<PROGRAM NAME=\"test\" EXE_PATH=\"/test\" EXE_FORMAT=\"test\" IMAGE_BASE=\"1000\">" +
				"<INFO_SOURCE USER=\"user\" TOOL=\"Ida-ProXYZ\" TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" />" +
				"<PROCESSOR NAME=\"METAPC\" ADDRESS_MODEL=\"32-bit\" ENDIAN=\"little\" />" +
				"<COMPILER NAME=\"windows\"/> </PROGRAM>")) {

			// list includes all languages
			checkValidXMLLoadSpec(byteProvider, loader.findSupportedLoadSpecs(byteProvider),
				"TEST4", Endian.LITTLE, "x86", "windows", "x86:LE:32:default");
		}
	}

	@Test
	public void testXmlFromGhidra() throws Exception {

		//@formatter:off
		String xml =
			"<PROGRAM NAME=\"test\" " +
						"EXE_PATH=\"/test\" " +
						"EXE_FORMAT=\"test\" " +
						"IMAGE_BASE=\"1000\">\n" +
				"<INFO_SOURCE USER=\"user\" " +
						"TOOL=\"Ghidra 1.2.3\" " +
						"TIMESTAMP=\"Fri Feb 06 12:06:53 EST 2015\" />\n" +
				"<PROCESSOR NAME=\"x86\" " +
						"LANGUAGE_PROVIDER=\"x86:LE:32:default:windows\" " +
						"ENDIAN=\"little\" />\n" +
			"</PROGRAM>";
		//@formatter:on

		try (ByteProvider byteProvider = getByteProvider("TEST5", xml)) {

			// list includes all languages
			checkValidXMLLoadSpec(byteProvider, loader.findSupportedLoadSpecs(byteProvider),
				"TEST5", Endian.LITTLE, "x86", "windows", "x86:LE:32:default");
		}
	}

	private void checkValidXMLLoadSpec(ByteProvider provider, Collection<LoadSpec> loadSpecs,
			String filename, Endian endian, String processorName, String oneCspec,
			String... languageIds) throws Exception {

		if (oneCspec != null) {
			// if oneCspec specified - this indicates single match
			assertEquals("Expected one load spec", 1, loadSpecs.size());
		}
		else if (loadSpecs.size() <= 1) {
			fail("Expected multiple load specs - found none");
		}

		LoadSpec firstLoadSpec = loadSpecs.iterator().next();
		assertTrue(firstLoadSpec.getLoader() instanceof XmlLoader);
		assertEquals(filename, firstLoadSpec.getLoader().getPreferredFileName(provider));

		for (LoadSpec loadSpec : loadSpecs) {
			LanguageDescription languageDescription =
				loadSpec.getLanguageCompilerSpec().getLanguageDescription();
			assertNotNull(languageDescription);
			CompilerSpecDescription compilerSpecDescription =
				loadSpec.getLanguageCompilerSpec().getCompilerSpecDescription();
			assertNotNull(compilerSpecDescription);
			if (endian != null) {
				assertEquals(endian, languageDescription.getEndian());
			}
			if (processorName != null) {
				assertEquals(processorName, languageDescription.getProcessor().toString());
			}
			if (oneCspec != null) {
				assertTrue(loadSpec.isPreferred());
				assertEquals(oneCspec, compilerSpecDescription.getCompilerSpecID().toString());
			}
			else {
				assertFalse(loadSpec.isPreferred());
			}
		}

		// All listed language IDs should be included
		for (String id : languageIds) {
			boolean found = false;
			for (LoadSpec loadSpec : loadSpecs) {
				if (id.equals(
					loadSpec.getLanguageCompilerSpec().getLanguageDescription().getLanguageID().toString())) {
					found = true;
					break;
				}
			}
			assertTrue("Expected to " + id + " to be included in load specs", found);
		}

	}

	private ByteProvider getByteProvider(String name, String text) throws IOException {

		File f = new File(getTestDirectoryPath(), "test.xml");
		f.deleteOnExit();

		FileUtilities.copyStreamToFile(new ByteArrayInputStream(text.getBytes()), f, false,
			TaskMonitor.DUMMY);

		Msg.debug(this, "Wrote text to file: " + f);

		// XMLImporterLoader requires a real file backed byte provider
		// but does not actual use byte provider
		return new ByteProvider() {

			@Override
			public byte[] readBytes(long index, long length) throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public byte readByte(long index) throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public long length() throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public boolean isValidIndex(long index) {
				throw new UnsupportedOperationException();
			}

			@Override
			public String getName() {
				return name;
			}

			@Override
			public InputStream getInputStream(long index) throws IOException {
				throw new UnsupportedOperationException();
			}

			@Override
			public File getFile() {
				return f;
			}

			@Override
			public String getAbsolutePath() {
				return f.getAbsolutePath();
			}

			@Override
			public void close() throws IOException {
				f.delete();
			}
		};
	}

}
