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
import ghidra.features.base.values.AddressValue;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;

public class AddressValueTest extends AbstractValueIntegrationTest {
	private static final String NAME = "Start Address";
	protected AddressFactory factory = createAddressFactory();

	@Test
	public void testAddressValueNoDefault() {
		values.defineAddress(NAME, null, factory);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setAddress(NAME, addr(13));
		assertTrue(values.hasValue(NAME));

		assertEquals(addr(13), values.getAddress(NAME));
	}

	@Test
	public void testAddressValueWithDefault() {
		values.defineAddress(NAME, addr(1), factory);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(addr(1), values.getAddress(NAME));

		values.setAddress(NAME, addr(2));
		assertTrue(values.hasValue(NAME));

		assertEquals(addr(2), values.getAddress(NAME));

		values.setAddress(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		AddressValue value1 = new AddressValue(NAME, addr(0x123), factory);
		AddressValue value2 = new AddressValue(NAME, null, factory);
		assertEquals("A:00000123", value1.getAsText());
		assertNull(value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		AddressValue v = new AddressValue(NAME, null, factory);
		assertEquals(addr(0x123), v.setAsText("A:00000123"));
		try {
			v.setAsText("xdsf");
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
		try {
			v.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineAddress(NAME, null, factory);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getAddress(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineAddress(NAME, null, factory);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnAddressInput(values.getAbstractValue(NAME), "2");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(addr(2), values.getAddress(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineAddress(NAME, addr(1), factory);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(addr(1), values.getAddress(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineAddress(NAME, addr(1), factory);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnAddressInput(values.getAbstractValue(NAME), "2");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(addr(2), values.getAddress(NAME));
	}

	private Address addr(int offset) {
		return factory.getDefaultAddressSpace().getAddress(offset);
	}

	protected void setTextOnAddressInput(AbstractValue<?> nameValue, String text) {
		runSwing(() -> {
			AddressInput addressInput = (AddressInput) nameValue.getComponent();
			addressInput.setValue(text);
		});
	}
}
