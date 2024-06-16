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

import org.jdom.Element;
import org.junit.Before;
import org.junit.Test;

public class SaveStateTest {
	private SaveState saveState;

	@Before
	public void setUp() {
		saveState = new SaveState("foo");
	}

	@Test
	public void testSubSaveStateToXml() throws Exception {
		SaveState subState = new SaveState("sub");
		subState.putInt("a", 5);
		subState.putString("foo", "bar");

		saveState.putSaveState("TEST", subState);
		saveState.putString("xxx", "zzzz");

		SaveState restoredState = saveAndRestoreToXml();

		// make sure our value is inside
		assertEquals("zzzz", restoredState.getString("xxx", null));
		SaveState restoreSubState = restoredState.getSaveState("TEST");
		assertEquals(2, restoreSubState.getNames().length);
		assertEquals(5, restoreSubState.getInt("a", 0));
		assertEquals("bar", restoreSubState.getString("foo", ""));
	}

	private SaveState saveAndRestoreToXml() throws Exception {
		Element saveToXml = saveState.saveToXml();
		return new SaveState(saveToXml);
	}
}
