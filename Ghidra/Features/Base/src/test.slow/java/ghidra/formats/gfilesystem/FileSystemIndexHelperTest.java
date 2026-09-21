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
import java.util.List;

import org.junit.Test;

import ghidra.app.util.bin.ByteProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class FileSystemIndexHelperTest {

	@Test
	public void testMaxFiles() throws IOException {
		FSRLRoot fsFSRL = FSRLRoot.makeRoot("dummy");
		FileSystemIndexHelper<Object> fsih =
			new FileSystemIndexHelper<Object>(new DummyFileSystem(), fsFSRL);

		for (int i = 0; i < FileSystemIndexHelper.MAX_FILEENTRY_COUNT; i++) {
			fsih.storeFile("file" + i, -1, false, 1, null);
		}

		try {
			fsih.storeFile("toomuch", -1, false, 1, null);
			fail("Should not get here");
		}
		catch (IOException e) {
			// good
		}
	}

	private static class DummyFileSystem implements GFileSystem {

		@Override
		public void close() throws IOException {
			// empty dummy

		}

		@Override
		public GFile lookup(String path) throws IOException {
			// empty dummy
			return null;
		}

		@Override
		public boolean isClosed() {
			// empty dummy
			return false;
		}

		@Override
		public FileSystemRefManager getRefManager() {
			// empty dummy
			return null;
		}

		@Override
		public String getName() {
			// empty dummy
			return null;
		}

		@Override
		public List<GFile> getListing(GFile directory) throws IOException {
			// empty dummy
			return null;
		}

		@Override
		public FSRLRoot getFSRL() {
			// empty dummy
			return null;
		}

		@Override
		public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
				throws IOException, CancelledException {
			// empty dummy
			return null;
		}
	}

}
