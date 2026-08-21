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
package docking.widgets.textfield;

import static org.junit.Assert.*;

import java.awt.FontMetrics;

import org.junit.Test;

import docking.test.AbstractDockingTest;

public class ElidingFilePathTextFieldTest extends AbstractDockingTest {

	@Test
	public void testBasicTrunc() {
		assertElide("/dir1/di.../filename", "/dir1/dir2222/filename", 20);
		assertElide("dir1/dir.../filename", "dir1/dir2222/filename", 20);

		// never truncate filename
		assertElide("..../filename", "/dir1/dir2222/filename", 1);
		assertElide("filename", "filename", 1);

		assertElide("/", "/", 1);
		assertElide("/", "/", 0);

		assertElide("", "", 1);
	}

	@Test
	public void testEllipseMerge() {
		// 2 long path elements are removed and then merged together into a single "...." 4-dot
		assertElide("/dir1/d.../directory3/filename", "/dir1/directory2/directory3/filename", 30);
		assertElide("/dir1/.../directory3/filename", "/dir1/directory2/directory3/filename", 29);
		assertElide("/dir1/.../d.../filename", "/dir1/directory2/directory3/filename", 23);
		assertElide("/dir1/..../filename", "/dir1/directory2/directory3/filename", 22);

		// 2 long non-adjacent path elements are removed and not merged
		assertElide("/dir1/.../dir3/d.../filename", "/dir1/directory2/dir3/directory4/filename",
			28);
		assertElide("/dir1/.../dir3/.../filename", "/dir1/directory2/dir3/directory4/filename", 27);
		assertElide("/dir1/..../filename", "/dir1/directory2/dir3/directory4/filename", 26);
	}

	@Test
	public void testEllipsesSpecialness() {
		// test that ellipses are used as replacement sequences in the output string, but dots are
		// not special or cause problems when used as input

		assertElide("/dir1/di.../filename", "/dir1/dir2.../filename", 20);

		// the long path element "directory3" is removed first and the similar "..." paths are not
		// touched or merged (until required to be removed to achieve requested shortness)
		assertElide("/dir1/.../.../directo.../filename", "/dir1/.../.../directory3/filename", 34);
		assertElide("/dir1/.../.../d.../filename", "/dir1/.../.../directory3/filename", 27);
		assertElide("/dir1/.../.../.../filename", "/dir1/.../.../directory3/filename", 26);
		assertElide("/dir1/..../filename", "/dir1/.../.../directory3/filename", 25);

		// double-dots (shorter than replacement ellipses) are not treated specially
		assertElide("/d.../../../filename", "/dir1/../../filename", 20);
		assertElide(".../../../filename", "/dir1/../../filename", 19);
		assertElide(".../../../filename", "/dir1/../../filename", 18);
		assertElide("..../../filename", "/dir1/../../filename", 17);
	}

	@Test
	public void testSequence() {
		// test progression of the shortened text.  The exact locations of the shortening
		// is not important, but should only change if the logic is updated.
		// This also gives you a visual understanding of how strings are shortened.

		//@formatter:off
		assertElide("/directory1/directory.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 64);
		assertElide("/directory1/director.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 63);
		assertElide("/directory1/directo.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 62);
		assertElide("/directory1/direct.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 61);
		assertElide("/directory1/direc.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 60);
		assertElide("/directory1/dire.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 59);
		assertElide("/directory1/dir.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 58);
		assertElide("/directory1/di.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 57);
		assertElide("/directory1/d.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 56);
		assertElide("/directory1/.../directory3/dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 55);
		assertElide("/directory1/.../direct.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 54);
		assertElide("/directory1/.../direc.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 53);
		assertElide("/directory1/.../dire.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 52);
		assertElide("/directory1/.../dir.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 51);
		assertElide("/directory1/.../di.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 50);
		assertElide("/directory1/.../d.../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 49);
		assertElide("/directory1/..../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 48);
		assertElide("/directory1/..../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 47);
		assertElide("/directory1/..../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 46);
		assertElide("/directory1/..../dir4/longdirectory5/filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 45);
		assertElide("/directory1/..../dir4/longdirect.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 44);
		assertElide("/directory1/..../dir4/longdirec.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 43);
		assertElide("/directory1/..../dir4/longdire.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 42);
		assertElide("/directory1/..../dir4/longdir.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 41);
		assertElide("/directory1/..../dir4/longdi.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 40);
		assertElide("/directory1/..../dir4/longd.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 39);
		assertElide("/directory1/..../dir4/long.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 38);
		assertElide("/directory1/..../dir4/lon.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 37);
		assertElide("/directory1/..../dir4/lo.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 36);
		assertElide("/directory1/..../dir4/l.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 35);
		assertElide("/directory1/..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 34);
		assertElide("/direct.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 33);
		assertElide("/direc.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 32);
		assertElide("/dire.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 31);
		assertElide("/dir.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 30);
		assertElide("/di.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 29);
		assertElide("/d.../..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 28);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 27);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 26);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 25);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 24);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 23);
		assertElide("..../dir4/.../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 22);
		assertElide("..../filename", "/directory1/directoryTwo/directory3/dir4/longdirectory5/filename", 21);
		//@formatter:on
	}

	static class TestElidingFilePathTextField extends ElidingFilePathTextField {

		@Override
		protected boolean isShortEnough(String s, FontMetrics fm, int maxWidth) {
			// conflate string length (chars) with rendered string width (pixels) to make this
			// testable without needing an actual font / fontmetrics and to startup swing.
			return s.length() <= maxWidth;
		}

		@Override
		public String getPreviewString(String s, FontMetrics fm, int maxWidth) {
			// republish this method as public
			return super.getPreviewString(s, fm, maxWidth);
		}

	}

	private static void assertElide(String expected, String orig, int len) {
		TestElidingFilePathTextField tf = new TestElidingFilePathTextField();
		assertEquals(expected, tf.getPreviewString(orig, null, len));
	}
}
