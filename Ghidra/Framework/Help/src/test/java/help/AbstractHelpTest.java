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
package help;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.nio.file.*;

import org.junit.After;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import utilities.util.FileUtilities;

public abstract class AbstractHelpTest extends AbstractGenericTest {

	protected static final String HELP_FILENAME_PREFIX = "Fake";
	protected static final String HELP_FILENAME = HELP_FILENAME_PREFIX + ".html";

	private Path testTempDir;

	public AbstractHelpTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		testTempDir = Files.createTempDirectory(testName.getMethodName());
	}

	@After
	public void tearDown() throws Exception {
		FileUtilities.deleteDir(testTempDir.toFile());
	}

	protected Path createHelpBuildOutputDir() throws IOException {
		Path out = testTempDir.resolve("build/help/main/help");
		Files.createDirectories(out);
		return out;
	}

	protected Path createFakeHelpTopic(Path helpDir) throws IOException {
		return createFakeHelpTopic("FakeTopic", helpDir);
	}

	protected Path createFakeHelpTopic(String topicName, Path helpDir) throws IOException {
		Path topicsDir = helpDir.resolve("topics");
		Path fakeTopicDir = topicsDir.resolve(topicName);
		Files.createDirectories(fakeTopicDir);
		return fakeTopicDir;
	}

	protected Path createTempHelpDir() throws IOException {
		Path helpDir = testTempDir.resolve("help");
		Files.createDirectory(helpDir);
		return helpDir;
	}

	protected void addRequiredHelpDirStructure(Path helpDir) throws IOException {

		// HelpFile wants to read one of these, so put one there
		createEmpty_TOC_Source_File(helpDir);
		createSharedDir(helpDir);
	}

	protected Path createSharedDir(Path helpDir) throws IOException {
		Path sharedDir = helpDir.resolve("shared");
		Files.createDirectory(sharedDir);

		Path css = sharedDir.resolve("Frontpage.css");
		Files.createFile(css);

		Path png = sharedDir.resolve("test.png");
		Files.createFile(png);

		return sharedDir;
	}

	protected Path createEmpty_TOC_Source_File(Path dir) throws IOException {

		Path fullTOCPath = dir.resolve("TOC_Source.xml");
		Path file = Files.createFile(fullTOCPath);

		//@formatter:off
	    String TOCXML =  "<?xml version='1.0' encoding='ISO-8859-1' ?>\n" + 
	    			     "<!-- Auto-generated on Fri Apr 03 09:37:08 EDT 2015 -->\n\n" + 
	    			     
						 "<tocroot>\n" +
						 "</tocroot>\n";
	    //@formatter:on

		Files.write(file, TOCXML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	protected Path createHelpContent(Path topic, String anchor) throws IOException {
		Path htmlPath = topic.resolve(HELP_FILENAME);
		Path file = Files.createFile(htmlPath);

		if (anchor == null) {
			anchor = "Default_Anchor";
		}

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   
		   "<BODY>\n" + 
		   "    <H1><A name=\""+anchor+"\"></A>Configure Tool</H1>\n" +
		   "    Some text with reference to shared image <IMG src=\"../../shared/test.png\">\n" +
		   "    \n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	protected Path createHelpContent_WithReferenceHREF(Path topic, String HREF) throws IOException {
		Path htmlPath = topic.resolve(HELP_FILENAME);
		Path file = Files.createFile(htmlPath);

		assertNotNull("Must specify the A tag HREF attribute", HREF);

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   
		   "<BODY>\n" + 
		   "    <H1><A name=\"Fake_Anchor\"></A>Configure Tool</H1>\n" +
		   "    And this is a link <A HREF=\""+HREF+"\">Click Me</A>" + 
		   "    \n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	protected Path createHelpContent_WithReferenceIMG_SRC(Path topic, String SRC)
			throws IOException {
		Path htmlPath = topic.resolve(HELP_FILENAME);
		Path file = Files.createFile(htmlPath);

		assertNotNull("Must specify the A tag SRC attribute", SRC);

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   
		   "<BODY>\n" + 
		   "    <H1><A name=\"Fake_Anchor\"></A>Configure Tool</H1>\n" +
		   "    Some text with reference to shared image <IMG src=\""+SRC+"\">\n" + 
		   "    \n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	protected void copy(Path from, Path to) throws Exception {

		FileUtilities.copyDir(from.toFile(), to.toFile(), null);
	}
}
