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

import static org.junit.Assert.*;

import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Test;

public class HelpBuildUtilsTest extends AbstractHelpTest {

	private static final String HELP_TOPIC_PATH = "/some/fake/path/to/help/topics";
	private static final String TOPIC_AND_FILENAME = "FooTopic/FooFile.html";
	private static final String HTML_FILE_PATH = HELP_TOPIC_PATH + '/' + TOPIC_AND_FILENAME;

	public HelpBuildUtilsTest() {
		super();
	}

	@Test
	public void testGetRelativeHelpPath() {
		String relativeString = "help/topics/FooTopic/FooFile.html";
		Path path = Paths.get("/some/fake/path/to/" + relativeString);
		Path relative = HelpBuildUtils.relativizeWithHelpTopics(path);
		assertEquals(relativeString, relative.toString());
	}

	@Test
	public void testGetRelativeHelpPath_NoHelpTopicInPath() {
		String invalidRelativeString = "help/topicz/" + TOPIC_AND_FILENAME;
		Path path = Paths.get("/some/fake/path/to/" + invalidRelativeString);
		Path relative = HelpBuildUtils.relativizeWithHelpTopics(path);
		assertNull(relative);
	}

	@Test
	public void testLocateReference_Local_HelpSystemSyntax() throws URISyntaxException {
		Path sourceFile = Paths.get(HTML_FILE_PATH);
		String reference = "help/topics/shared/foo.png";
		Path resolved = HelpBuildUtils.locateReference(sourceFile, reference);
		assertEquals("Help System syntax was not preserved", Paths.get(reference), resolved);
	}

	@Test
	public void testLocateReference_Local_RelativeSyntax() throws URISyntaxException {
		Path sourceFile = Paths.get(HTML_FILE_PATH);
		String reference = "../shared/foo.png";// go up one to the help dir
		Path resolved = HelpBuildUtils.locateReference(sourceFile, reference);
		assertEquals("Relative syntax did not locate file",
			Paths.get(HELP_TOPIC_PATH + "/shared/foo.png"), resolved);
	}

	@Test
	public void testLocateReference_Remote() throws URISyntaxException {
		Path sourceFile = Paths.get(HTML_FILE_PATH);
		String reference = "http://some.fake.server/foo.png";
		Path resolved = HelpBuildUtils.locateReference(sourceFile, reference);
		assertNull(resolved);
		boolean isRemote = HelpBuildUtils.isRemote(reference);
		assertTrue(isRemote);
	}

	@Test
	public void testLocateReferences_Icons() throws URISyntaxException {
		Path sourceFile = Paths.get(HTML_FILE_PATH);
		String reference = "Icons.REFRESH_ICON"; // see Icons class
		ImageLocation location = HelpBuildUtils.locateImageReference(sourceFile, reference);
		Path resolved = location.getResolvedPath();
		String name = resolved.getFileName().toString();
		assertEquals("Help System syntax was not preserved", "reload3.png", name);
		assertTrue(location.isRuntime());
		assertFalse(location.isRemote());
	}

	@Test
	public void testLocateReferences_Icons_BadName() throws URISyntaxException {
		Path sourceFile = Paths.get(HTML_FILE_PATH);
		String reference = "Icons.REFRESH_ICON_BAD";  // non-existent
		ImageLocation location = HelpBuildUtils.locateImageReference(sourceFile, reference);
		Path resolved = location.getResolvedPath();
		assertNull(resolved);
	}
}
