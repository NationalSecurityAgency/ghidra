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
package ghidra.net;

import static org.junit.Assert.*;

import java.net.URI;
import java.net.URISyntaxException;

import org.junit.Test;

public class UriUtilTest {

	@Test
	public void testAppendPathEmptyPath() throws URISyntaxException {
		assertEquals("http://host", UriUtil.appendPath(new URI("http://host")).toString());
		assertEquals("http://host/dir1",
			UriUtil.appendPath(new URI("http://host"), "dir1").toString());
	}

	@Test
	public void testAppendPathForcePathTerm() throws URISyntaxException {
		assertEquals("http://host/", UriUtil.appendPath(new URI("http://host"), "/").toString());
	}

	@Test
	public void testAppendPathSkipEmptyNullElements() throws URISyntaxException {
		assertEquals("http://host", UriUtil.appendPath(new URI("http://host"), "").toString());
		assertEquals("http://host/dir1",
			UriUtil.appendPath(new URI("http://host"), "", null, "dir1").toString());
	}

	@Test
	public void testAppendPathSpaces() throws URISyntaxException {
		assertEquals("http://host/dir%20name",
			UriUtil.appendPath(new URI("http://host"), "dir name").toString());
		assertEquals("/dir name",
			UriUtil.appendPath(new URI("http://host"), "dir name").getPath());
	}

	@Test
	public void testAppendPathDotdots() throws URISyntaxException {
		assertEquals("http://host/dir1/../../dir2",
			UriUtil.appendPath(new URI("http://host"), "dir1", "..", "..", "dir2").toString());
	}

	@Test
	public void testAppendPathEscapedSlashesNotPreserved() throws URISyntaxException {
		// Show the difference between normal '/' chars and %2F encoded slash chars in normal URI
		// and a URI constructed with appendPath()

		URI uri = new URI("http://host/dir%2Fname/dir2");
		assertEquals("/dir/name/dir2", uri.getPath());
		assertEquals("/dir%2Fname/dir2", uri.getRawPath());

		uri = UriUtil.appendPath(new URI("http://host/dir%2Fname"), "dir2");
		assertEquals("http://host/dir/name/dir2", uri.toString());
		assertEquals("/dir/name/dir2", uri.getPath());
		assertEquals("/dir/name/dir2", uri.getRawPath());
	}

	@Test
	public void testAppendPathKeepFrag() throws URISyntaxException {
		assertEquals("http://host/dir1#frag",
			UriUtil.appendPath(new URI("http://host#frag"), "dir1").toString());
	}

	@Test
	public void testAppendPathAllASCIIChars() throws URISyntaxException {
		String s = "";
		for (char ch = ' '; ch < 0x7f; ch++) {
			s += ch;
		}
		URI uri = UriUtil.appendPath(new URI("http://host"), s);
		assertEquals("/" + s, uri.getPath());
	}
}
