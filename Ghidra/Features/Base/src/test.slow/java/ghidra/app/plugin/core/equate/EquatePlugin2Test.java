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
package ghidra.app.plugin.core.equate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * Tests the Equate Plugin functionality.
 */
public class EquatePlugin2Test extends AbstractEquatePluginTest {

	@Test
	public void testApplyEnumActionEnabled() {

		assertFalse(applyEnumAction.isEnabledForContext(getListingContext()));

		putCursorOnOperand(0x010064c5, 1);
		assertFalse(applyEnumAction.isEnabledForContext(getListingContext())); // existing equate exists

		removeAction.actionPerformed(getListingContext()); // remove existing equate
		waitForBusyTool(tool);

		assertTrue(applyEnumAction.isEnabledForContext(getListingContext()));

		selectRange(addr(0x0100644c), addr(0x01006458));
		assertTrue(applyEnumAction.isEnabledForContext(getListingContext()));
	}

}
