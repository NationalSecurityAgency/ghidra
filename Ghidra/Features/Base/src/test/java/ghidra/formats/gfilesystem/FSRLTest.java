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
package ghidra.formats.gfilesystem;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.MalformedURLException;

import org.junit.Test;

public class FSRLTest {

	@Test
	public void testFSRLBuilders() {
		FSRL fsrl1 = FSRLRoot.makeRoot("file").withPath("blah");
		assertEquals("file://blah", fsrl1.toString());

		FSRL fsrl2 = fsrl1.withPath("newpath");
		assertEquals("file://newpath", fsrl2.toString());

		FSRL nestedFS = FSRLRoot.nestedFS(fsrl1, "subfs");
		assertEquals("file://blah|subfs://", nestedFS.toString());

		FSRL fsrl3 = fsrl1.appendPath("relpath");
		assertEquals("file://blah/relpath", fsrl3.toString());

		FSRL fsrl4 = fsrl1.appendPath("/relpath");
		assertEquals("file://blah/relpath", fsrl4.toString());
	}

	@Test
	public void testEmptyFSRL() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://");
		assertEquals("fsrl", fsrl.getFS().getProtocol());
		assertNull(fsrl.getPath());
		assertNull(fsrl.getName());
		assertNull(fsrl.getMD5());
	}

	@Test(expected = MalformedURLException.class)
	public void testEmptyStr() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("");
	}

	@Test
	public void testSpecialChars() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://a:/path/filename+$dollar%20%7cblah?params");
		assertEquals("fsrl", fsrl.getFS().getProtocol());
		assertEquals("a:/path/filename+$dollar |blah", fsrl.getPath());
		assertEquals("filename+$dollar |blah", fsrl.getName());
	}

	@Test
	public void testDOSPaths() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://a:\\dir\\filename.txt");
		assertEquals("fsrl", fsrl.getFS().getProtocol());
		assertEquals("a:/dir/filename.txt", fsrl.getPath());
	}

	@Test
	public void testCharEncode() throws MalformedURLException {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 255; i++) {
			char c = (char) (i & 0xff);
			sb.append(c);
		}
		String orig = sb.toString();
		String encoded = FSUtilities.escapeEncode(orig);
		String decoded = FSUtilities.escapeDecode(encoded);
		assertEquals(orig, decoded);
	}

	@Test
	public void testCharEncodeExtended() throws MalformedURLException {
		String orig = "test\u01a51299";
		String encoded = FSUtilities.escapeEncode(orig);
		String decoded = FSUtilities.escapeDecode(encoded);
		assertEquals(orig, decoded);
	}

	@Test
	public void testCharEncodeExtended2() throws MalformedURLException {
		String orig = "test\u01a5\u01a61299";
		String encoded = FSUtilities.escapeEncode(orig);
		String decoded = FSUtilities.escapeDecode(encoded);
		assertEquals(orig, decoded);
	}

	@Test
	public void testStringFormat() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile");

		assertEquals("string format bad", "fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile",
			fsrl.toString());
		assertEquals("pretty string format bad", "fsrl://path/filename|subfsrl://subpath/subfile",
			fsrl.toPrettyString());
		assertEquals("partial string format bad", "subfsrl://subpath/subfile", fsrl.toStringPart());

		assertEquals("pretty full string format bad", "path/filename|subpath/subfile",
			fsrl.toPrettyFullpathString());
	}

	@Test
	public void testStringFormat2() throws MalformedURLException {
		FSRL fsrl =
			FSRL.fromString("fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile|sub2://");

		assertEquals("string format bad",
			"fsrl://path/filename?MD5=1234|subfsrl://subpath/subfile|sub2://", fsrl.toString());
		assertEquals("pretty string format bad",
			"fsrl://path/filename|subfsrl://subpath/subfile|sub2://", fsrl.toPrettyString());
		assertEquals("partial string format bad", "sub2://", fsrl.toStringPart());
		assertEquals("pretty full string format bad", "path/filename|subpath/subfile|",
			fsrl.toPrettyFullpathString());
	}

	@Test
	public void testStringFormat3() throws MalformedURLException {
		FSRL fsrl =
			FSRL.fromString("fsrl:///path/filename?MD5=1234|subfsrl:///subpath/subfile|sub2://");

		assertEquals("string format bad",
			"fsrl:///path/filename?MD5=1234|subfsrl:///subpath/subfile|sub2://", fsrl.toString());
		assertEquals("pretty string format bad",
			"fsrl:///path/filename|subfsrl:///subpath/subfile|sub2://", fsrl.toPrettyString());
		assertEquals("partial string format bad", "sub2://", fsrl.toStringPart());
		assertEquals("pretty full string format bad", "/path/filename|/subpath/subfile|",
			fsrl.toPrettyFullpathString());
	}

	@Test
	public void testNameDepth() throws IOException {
		FSRL fsrl = FSRL.fromString(
			"fsrl://path/rootfile|sub1://path/file1|sub2://path/file2|sub3://path/file3");

		assertEquals("bad name", "file3", fsrl.getName());
		assertEquals("bad name", "file3", fsrl.getName(0));
		assertEquals("bad name", "file2", fsrl.getName(1));
		assertEquals("bad name", "file1", fsrl.getName(2));
		assertEquals("bad name", "rootfile", fsrl.getName(3));
		try {
			fsrl.getName(4);
			fail("Should not get a value");
		}
		catch (IOException ioe) {
			// good
		}
	}

	/**
	 * Test 'equiv' of FSRL w/md5 to string, where MD5 is ignored.
	 *
	 * @throws MalformedURLException
	 */
	@Test
	public void testEquiv1() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://path/rootfile?MD5=00000000000000000000000000000000");
		String testStr1 = "fsrl://path/rootfile";
		assertTrue(fsrl.isEquivalent(testStr1));
		assertFalse(fsrl.isEquivalent(testStr1.substring(0, testStr1.length() - 1)));

		String testStr2 = "fsrl://path/rootfile?MD5=BADBEEF0000000000000000000000000";
		assertFalse(fsrl.isEquivalent(testStr2));
	}

	/**
	 * Test 'equiv' of FSRL to string w/md5, where MD5 is ignored.
	 *
	 * @throws MalformedURLException
	 */
	@Test
	public void testEquiv2() throws MalformedURLException {
		FSRL fsrl = FSRL.fromString("fsrl://path/rootfile");
		String testStr1 = "fsrl://path/rootfile?MD5=00000000000000000000000000000000";
		assertTrue(fsrl.isEquivalent(testStr1));
		assertFalse(fsrl.isEquivalent(testStr1.substring(0, testStr1.length() - 1)));
	}

	@Test
	public void testIsDescendantOf1() throws MalformedURLException {
		FSRL parentFSRL = FSRL.fromString("file:///subdir1/subdir2/containerfile.zip");
		FSRL childFSRL =
			FSRL.fromString("file:///subdir1/subdir2/containerfile.zip|subfs:///subfs.file");
		FSRL notParentFSRL = FSRL.fromString("file:///subdir1/subdir2/containerfile.zipx");

		assertTrue(parentFSRL.toString() + " should be parent of " + childFSRL.toString(),
			childFSRL.isDescendantOf(parentFSRL));
		assertFalse(childFSRL.isDescendantOf(notParentFSRL));
		assertFalse(childFSRL.isDescendantOf(childFSRL));
	}

	@Test
	public void testIsDescendantOf1a() throws MalformedURLException {
		FSRL childFSRL = FSRL.fromString(
			"file:///subdir1/subdir2/containerfile.zip|file:///containerfile2.zip|subfs:///subfs.file");
		FSRL siblingFSRL = FSRL.fromString(
			"file:///subdir1/subdir2/containerfile.zip|file:///containerfile2.zip|subfs:///subfs.file2");
		FSRL rootDirFSRL = FSRL.fromString(
			"file:///subdir1/subdir2/containerfile.zip|file:///containerfile2.zip|subfs:///");
		FSRL parentFSRL =
			FSRL.fromString("file:///subdir1/subdir2/containerfile.zip|file:///containerfile2.zip");
		FSRL notParentFSRL =
			FSRL.fromString("file:///subdir1/subdir2/containerfile.zip|notx:///containerfile2.zip");
		FSRL gParentFSRL = FSRL.fromString("file:///subdir1/subdir2/containerfile.zip");
		FSRL gParentsDirFSRL = FSRL.fromString("file:///subdir1/subdir2");
		FSRL gParentsAlmostDirFSRL = FSRL.fromString("file:///subdir");
		FSRL notGParentFSRL = FSRL.fromString("file:///subdir1/subdir2/notcontainerfile.zip");

		assertTrue(parentFSRL.toString() + " should be parent of " + childFSRL.toString(),
			childFSRL.isDescendantOf(parentFSRL));
		assertTrue(gParentFSRL.toString() + " should be parent of " + childFSRL.toString(),
			childFSRL.isDescendantOf(gParentFSRL));
		assertTrue(gParentsDirFSRL.toString() + " should be parent of " + childFSRL.toString(),
			childFSRL.isDescendantOf(gParentsDirFSRL));
		assertTrue(rootDirFSRL.toString() + " should be parent of " + childFSRL.toString(),
			childFSRL.isDescendantOf(rootDirFSRL));
		assertFalse(childFSRL.isDescendantOf(notGParentFSRL));
		assertFalse(childFSRL.isDescendantOf(notParentFSRL));
		assertFalse(childFSRL.isDescendantOf(gParentsAlmostDirFSRL));
		assertFalse(childFSRL.isDescendantOf(siblingFSRL));
		assertFalse(childFSRL.isDescendantOf(childFSRL));
	}

	@Test
	public void testIsDescendantOf2() throws MalformedURLException {
		FSRL parentFSRL = FSRL.fromString("file:///subdir1/subdir2");
		FSRL childFSRL = FSRL.fromString("file:///subdir1/subdir2/file1.txt");

		assertTrue(childFSRL.isDescendantOf(parentFSRL));
	}
}
