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
package ghidra.features.base.values;

import static org.junit.Assert.*;

import org.junit.Test;

import docking.widgets.values.AbstractValue;
import ghidra.app.util.AddressInput;

public class ValuesMapDialogParseErrorTest extends AbstractValueIntegrationTest {

	@Test
	public void testParseErrorBlocksDialogFromClosing() {
		values.defineString("Name");
		values.defineAddress("Start", programA);
		values.defineInt("Size");
		showDialogOnSwingWithoutBlocking();
		setTextOnAddressInput(values.getAbstractValue("Start"), "sdfasf");
		pressOk();

		assertTrue(dialog.isShowing());
		assertTrue(dialog.getStatusText().startsWith("Error"));
		setTextOnAddressInput(values.getAbstractValue("Start"), "0");
		pressOk();
		assertFalse(dialog.isShowing());
	}

	protected void setTextOnAddressInput(AbstractValue<?> nameValue, String text) {
		runSwing(() -> {
			AddressInput addressInput = (AddressInput) nameValue.getComponent();
			addressInput.setValue(text);
		});
	}
}
