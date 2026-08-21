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
package ghidra.framework.data;

import static org.junit.Assert.*;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class RelativePathTest extends AbstractGenericTest {

	@Test
	public void testGetRelativePath() {

		// File links
		assertEquals("../b", GhidraFolderData.getRelativePath("/a/b/../b", "/a/b", false));
		assertEquals("../b", GhidraFolderData.getRelativePath("/a/b", "/a/b", false));
		assertEquals("c", GhidraFolderData.getRelativePath("/a/b/c", "/a/b", false));
		assertEquals("../c", GhidraFolderData.getRelativePath("/a/b/c", "/a/b/d", false));

		// Folder links
		assertEquals(".", GhidraFolderData.getRelativePath("/a/b/../b", "/a/b", true));
		assertEquals(".", GhidraFolderData.getRelativePath("/a/b", "/a/b", true));
		assertEquals("c", GhidraFolderData.getRelativePath("/a/b/c", "/a/b", true));
		assertEquals("../c", GhidraFolderData.getRelativePath("/a/b/c", "/a/b/d", true));
		assertEquals(".", GhidraFolderData.getRelativePath("/a/b/../b/", "/a/b", true)); // See Note-1
		assertEquals(".", GhidraFolderData.getRelativePath("/a/b/", "/a/b", true));
		assertEquals("c/", GhidraFolderData.getRelativePath("/a/b/c/", "/a/b", true));
		assertEquals("../c/", GhidraFolderData.getRelativePath("/a/b/c/", "/a/b/d", true));

	}

}
