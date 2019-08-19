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
package help.validator.model;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.nio.file.*;
import java.util.Collection;

import org.junit.Test;

import help.AbstractHelpTest;
import help.validator.*;
import help.validator.location.DirectoryHelpModuleLocation;

public class HelpFileTest extends AbstractHelpTest {

	@Test
	public void testGoodHTML() throws IOException {

		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);

		Path topic = createFakeHelpTopic(helpDir);

		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createGoodHTMLFile(topic);
		new HelpFile(helpLocation, html);

		// if we get here, then no exceptions happened
	}

	@Test
	public void testBadHTML_InvalidStyleSheet() throws Exception {

		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);

		Path topic = createFakeHelpTopic(helpDir);

		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createBadHTMLFile_InvalidStyleSheet(topic);

		try {
			new HelpFile(helpLocation, html);
			fail("Parsing did not fail for invalid stylesheet");
		}
		catch (Exception e) {
			// good
		}

	}

	@Test
	public void testBadHTML_InvalidAnchorRef_BadURI() throws Exception {

		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);

		Path topic = createFakeHelpTopic(helpDir);

		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createBadHTMLFile_InvalidAnchor_BadURI(topic);

		try {
			new HelpFile(helpLocation, html);
			fail("Parsing did not fail for invalid stylesheet");
		}
		catch (Exception e) {
			// good
		}
	}

	@Test
	public void testBadHTML_InvalidAnchorRef_WrongAttribtues() throws Exception {
		// no 'name' or 'href' attribute
		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);

		Path topic = createFakeHelpTopic(helpDir);

		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createBadHTMLFile_InvalidAnchor_WrongAttributes(topic);

		try {
			new HelpFile(helpLocation, html);
			fail("Parsing did not fail for invalid stylesheet");
		}
		catch (Exception e) {
			// good
		}
	}

	@Test
	public void testBadHTML_InvalidIMG_WrongAttribtues() throws Exception {
		// no 'src'
		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);

		Path topic = createFakeHelpTopic(helpDir);

		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createBadHTMLFile_InvalidIMG_WrongAttributes(topic);

		try {
			new HelpFile(helpLocation, html);
			fail("Parsing did not fail for invalid stylesheet");
		}
		catch (Exception e) {
			// good
		}
	}

	@Test
	public void testCommentGetsIgnored() throws Exception {

		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);
		Path topic = createFakeHelpTopic(helpDir);
		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());

		Path html = createGoodHTMLFile_InvalidAnchor_CommentedOut_MultiLineComment(topic);
		HelpFile helpFile = new HelpFile(helpLocation, html);
		Collection<HREF> hrefs = helpFile.getAllHREFs();
		assertTrue(hrefs.isEmpty());
	}

	// @Test 
	// for debugging a real help file
	public void test() throws Exception {

		Path path = Paths.get("<home dir>/<git>/ghidra/Ghidra/Features/" +
			"Base/src/main/help/help/topics/Annotations/Annotations.html");

		Path helpDir = createTempHelpDir();
		addRequiredHelpDirStructure(helpDir);
		DirectoryHelpModuleLocation helpLocation =
			new DirectoryHelpModuleLocation(helpDir.toFile());
		AnchorManager anchorManager = new AnchorManager();
		ReferenceTagProcessor tagProcessor = new ReferenceTagProcessor(helpLocation, anchorManager);
		HTMLFileParser.scanHtmlFile(path, tagProcessor);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	/** Has valid links */
	private Path createGoodHTMLFile(Path topic) throws IOException {
		String anchor = "ManagePluginsDialog";
		return createHelpContent(topic, anchor);
	}

	private Path createBadHTMLFile_InvalidAnchor_WrongAttributes(Path topic) throws IOException {
		Path htmlPath = topic.resolve("FakeHTML_WrongAttributes.html");
		Path file = Files.createFile(htmlPath);

		String badAttr = "bob=1";

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   "<BODY>\n" + 
		   "<H1><A name=\"ManagePluginsDialog\"></A>Configure Tool</H1>\n" +
		   "Some text with reference to shared image <a "+badAttr+">Click me</a>\n" +
		   "\n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	private Path createBadHTMLFile_InvalidIMG_WrongAttributes(Path topic) throws IOException {
		Path htmlPath = topic.resolve("FakeHTML_WrongAttributes.html");
		Path file = Files.createFile(htmlPath);

		String badAttr = "bob=1";

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   "<BODY>\n" + 
		   "<H1><A name=\"ManagePluginsDialog\"></A>Configure Tool</H1>\n" +
		   "Some text with reference to shared image <IMG "+badAttr+"s>\n" +
		   "\n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	private Path createBadHTMLFile_InvalidAnchor_BadURI(Path topic) throws IOException {
		Path htmlPath = topic.resolve("FakeHTML_BadURI.html");
		Path file = Files.createFile(htmlPath);

		String badURI = ":baduri"; // no scheme name on this URI

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   "<BODY>\n" + 
		   "<H1><A name=\"ManagePluginsDialog\"></A>Configure Tool</H1>\n" +
		   "Some text with reference to shared image <a href=\""+badURI+"\">Click me</a>\n" +
		   "\n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	private Path createBadHTMLFile_InvalidStyleSheet(Path topic) throws IOException {
		Path htmlPath = topic.resolve("FakeHTML_InvalidStyleSheet.html");
		Path file = Files.createFile(htmlPath);

		String badName = "bad_name";

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/"+badName+".css\">\n" +
		   "</HEAD>\n" +
		   "<BODY>\n" + 
		   "<H1><A name=\"ManagePluginsDialog\"></A>Configure Tool</H1>\n" +
		   "Some text with reference to shared image <IMG src=\"../../shared/test.png\">\n" +
		   "\n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}

	private Path createGoodHTMLFile_InvalidAnchor_CommentedOut_MultiLineComment(Path topic)
			throws IOException {
		Path htmlPath = topic.resolve("HTMLWithComment.html");
		Path file = Files.createFile(htmlPath);

		String badURI = ":baduri"; // no scheme name on this URI

		//@formatter:off
	    String HTML =  
	       "<HTML>\n" + 
		   "<HEAD>\n" + 
		   "<TITLE>Configure Tool</TITLE>\n" + 
		   "<LINK rel=\"stylesheet\" type=\"text/css\" href=\"../../shared/Frontpage.css\">\n" +
		   "</HEAD>\n" +
		   "<BODY>\n" + 
		   "<H1><A name=\"ManagePluginsDialog\"></A>Configure Tool</H1>\n" +
		   "    <!--" +
		   "    Some text with reference to shared image <a href=\""+badURI+"\">Click me</a>\n" +
		   "    -->" + 
		   "\n" +
		   "</BODY>\n" +
		   "</HTML>\n";
	    //@formatter:on

		Files.write(file, HTML.getBytes(), StandardOpenOption.CREATE);
		return file;
	}
}
