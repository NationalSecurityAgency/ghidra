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

import static org.junit.Assert.assertEquals;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Assert;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.util.exception.AssertException;

public class AnchorDefinitionTest extends AbstractGenericTest {

	public AnchorDefinitionTest() {
		super();
	}

@Test
    public void testFileWithoutAnchor() {
		// this should generate and ID that is the filename only
		Path fullPath = Paths.get("/fake/full/path/help/topics/TopicName/HelpFilename.html"); // dir case
		AnchorDefinition def = new AnchorDefinition(fullPath, null, 1);
		assertEquals("TopicName_HelpFilename", def.getId());
	}

@Test
    public void testFileInHelpTopicDir() {

		Path fullPath = Paths.get("/fake/full/path/help/topics/TopicName/HelpFilename.html"); // dir case
		AnchorDefinition def = new AnchorDefinition(fullPath, "anchor_1", 1);
		assertEquals("TopicName_anchor_1", def.getId());
	}

@Test
    public void testFileInHelpTopicJar() {
		Path fullPath = Paths.get("/help/topics/TopicName/HelpFilename.html"); // jar case
		AnchorDefinition def = new AnchorDefinition(fullPath, "anchor_1", 1);
		assertEquals("TopicName_anchor_1", def.getId());
	}

@Test
    public void testFileInHelpDir_NotUnderHelpTopic() {
		Path fullPath = Paths.get("/fake/full/path/help/HelpFilename.html"); // dir case

		try {
			new AnchorDefinition(fullPath, "anchor_1", 1);
			Assert.fail("Did not fail with file not living under a help topic directory");
		}
		catch (AssertException e) {
			// good
		}
	}
}
