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
package docking;

import static org.junit.Assert.assertEquals;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.KeyStroke;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DockingKeybindingActionTest extends AbstractGenericTest {

	public DockingKeybindingActionTest() {
		super();
	}

	@Test
	public void testKeybinding_Unmodified() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_C, 0);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("C");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_Unmodified_MixedCase() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_C, 0);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("C");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_Modifier() {

		KeyStroke javaKeyStroke =
			KeyStroke.getKeyStroke(KeyEvent.VK_COMMA, InputEvent.CTRL_DOWN_MASK);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("ctrl COMMA");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_MultipleModifiers() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_COMMA,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("ctrl shift COMMA");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_MultipleModifiersOutOfOrder() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_COMMA,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("ctrl COMMA shift");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_MultipleModifiers_MixedCase() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_COMMA,
			InputEvent.CTRL_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("ctrl SHIFT comma");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}

	@Test
	public void testKeybinding_InvalidControl() {

		KeyStroke javaKeyStroke = KeyStroke.getKeyStroke(KeyEvent.VK_C, InputEvent.CTRL_DOWN_MASK);
		KeyStroke dockingKeyStroke = DockingKeyBindingAction.parseKeyStroke("control C");
		assertEquals(javaKeyStroke, dockingKeyStroke);
	}
}
