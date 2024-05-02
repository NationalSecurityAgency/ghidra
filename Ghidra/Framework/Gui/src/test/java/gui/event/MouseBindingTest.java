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
package gui.event;

import static org.junit.Assert.*;

import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;

import javax.swing.JPanel;

import org.junit.Test;

public class MouseBindingTest {

	private static final int CTRL = InputEvent.CTRL_DOWN_MASK;
	private static final int SHIFT = InputEvent.SHIFT_DOWN_MASK;

	@Test
	public void testConstructor_InvalidButton() {

		try {
			new MouseBinding(0);
			fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		try {
			new MouseBinding(-1);
			fail();
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testGetMouseBinding_BadButton() {
		assertNull(MouseBinding.getMouseBinding("Button"));
		assertNull(MouseBinding.getMouseBinding("Button0"));
		assertNull(MouseBinding.getMouseBinding("Cats"));
		assertNull(MouseBinding.getMouseBinding("Buttons12"));
	}

	@Test
	public void testGetMouseBindingFromText() {

		MouseBinding mb = MouseBinding.getMouseBinding("Button1");
		int button = 1;
		assertEquals(button, mb.getButton());
		assertModifiers(mb, buttonMask(button));
		mb = MouseBinding.getMouseBinding("Button2");
		button = 2;
		assertEquals(button, mb.getButton());
		assertModifiers(mb, buttonMask(button));

		mb = MouseBinding.getMouseBinding("Ctrl+Button1");
		button = 1;
		assertEquals(button, mb.getButton());
		assertModifiers(mb, CTRL, buttonMask(button));

		mb = MouseBinding.getMouseBinding("Ctrl+Shift+Button2");
		button = 2;
		assertEquals(button, mb.getButton());
		assertModifiers(mb, CTRL, SHIFT, buttonMask(button));
	}

	@Test
	public void testGetMouseBindingFromEvent() {

		int button = 1;
		int modifiers = buttonMask(1);
		JPanel source = new JPanel();
		MouseEvent event = new MouseEvent(source, MouseEvent.MOUSE_PRESSED,
			System.currentTimeMillis(), modifiers, 0, 0, 1, false, button);
		MouseBinding mb = MouseBinding.getMouseBinding(event);
		assertEquals(button, mb.getButton());
		assertModifiers(mb, buttonMask(button));
	}

	@Test
	public void testIsMatchingRelease() {

		int button = 1;
		MouseBinding mb = new MouseBinding(button);

		int modifiers = buttonMask(1);
		JPanel source = new JPanel();
		MouseEvent pressed = new MouseEvent(source, MouseEvent.MOUSE_PRESSED,
			System.currentTimeMillis(), modifiers, 0, 0, 1, false, button);
		assertFalse(mb.isMatchingRelease(pressed));

		MouseEvent released = new MouseEvent(source, MouseEvent.MOUSE_RELEASED,
			System.currentTimeMillis(), modifiers, 0, 0, 1, false, button);
		assertTrue(mb.isMatchingRelease(released));

		MouseEvent clicked = new MouseEvent(source, MouseEvent.MOUSE_RELEASED,
			System.currentTimeMillis(), modifiers, 0, 0, 1, false, button);
		assertTrue(mb.isMatchingRelease(clicked));

		// test that modifiers are ignored when determining what is a matching release
		modifiers = InputEvent.SHIFT_DOWN_MASK ^ buttonMask(button);
		released = new MouseEvent(source, MouseEvent.MOUSE_RELEASED, System.currentTimeMillis(),
			modifiers, 0, 0, 1, false, button);
		assertTrue(mb.isMatchingRelease(released));
	}

	@Test
	public void testGetDisplayString() {

		int button = 1;
		MouseBinding mb = new MouseBinding(button);
		assertEquals("Button1", mb.getDisplayText());

		mb = MouseBinding.getMouseBinding("Button1");
		assertEquals("Button1", mb.getDisplayText());

		mb = MouseBinding.getMouseBinding("Button1 pressed");
		assertEquals("Button1", mb.getDisplayText());

		mb = MouseBinding.getMouseBinding("Shift+Button2");
		assertEquals("Shift+Button2", mb.getDisplayText());
	}

	private void assertModifiers(MouseBinding mb, int... expected) {
		int actual = mb.getModifiers();
		int allMods = 0;
		for (int mod : expected) {
			allMods ^= mod;
		}
		assertEquals(allMods, actual);
	}

	private int buttonMask(int buttonNumber) {
		return InputEvent.getMaskForButton(buttonNumber);
	}
}
