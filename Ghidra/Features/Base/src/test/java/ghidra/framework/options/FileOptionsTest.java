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
package ghidra.framework.options;

import static org.junit.Assert.*;

import java.awt.Color;
import java.io.File;
import java.io.IOException;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FileOptionsTest extends AbstractGenericTest {

	@Test
	public void testSavingRestoringFileOptions() throws IOException {
		FileOptions options = new FileOptions("Test");

		options.registerOption("aaa", Integer.valueOf(5), null, "aaa description");
		options.registerOption("bbb", Integer.valueOf(5), null, "bbb description");
		options.registerOption("ccc", Color.RED, null, "ccc description");

		TestCustomOption custom = new TestCustomOption("bob", 23, true);

		options.setInt("aaa", 10);
		options.setColor("ccc", Color.BLUE);
		options.setCustomOption("ddd", custom);

		assertEquals(10, options.getInt("aaa", 0));
		assertEquals(5, options.getInt("bbb", 0));
		assertEquals(Color.BLUE, options.getColor("ccc", null));
		assertEquals(custom, options.getCustomOption("ddd", null));

		File file = createTempFile("optionsFile", "options");

		options.save(file);

		FileOptions restored = new FileOptions(file);

		assertEquals(10, restored.getInt("aaa", 0));
		assertFalse(restored.contains("bbb"));		// default value should not have been saved
		assertEquals(Color.BLUE, restored.getColor("ccc", null));
		assertEquals(custom, restored.getCustomOption("ddd", null));
	}

	public static class TestCustomOption implements CustomOption {

		String name;
		int count;
		boolean active;

		public TestCustomOption() {

		}

		public TestCustomOption(String name, int count, boolean active) {
			this.name = name;
			this.count = count;
			this.active = active;
		}

		@Override
		public void readState(SaveState saveState) {
			name = saveState.getString("name", null);
			count = saveState.getInt("count", 0);
			active = saveState.getBoolean("active", false);
		}

		@Override
		public void writeState(SaveState saveState) {
			saveState.putString("name", name);
			saveState.putInt("count", count);
			saveState.putBoolean("active", active);
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + (active ? 1231 : 1237);
			result = prime * result + count;
			result = prime * result + ((name == null) ? 0 : name.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			TestCustomOption other = (TestCustomOption) obj;
			if (active != other.active) {
				return false;
			}
			if (count != other.count) {
				return false;
			}
			if (name == null) {
				if (other.name != null) {
					return false;
				}
			}
			else if (!name.equals(other.name)) {
				return false;
			}
			return true;
		}

	}

}
