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
package ghidra.app.plugin.core.debug.gui.model;

import java.awt.event.*;

import javax.swing.event.TreeExpansionEvent;

public interface Adapters {
	interface FocusListener extends java.awt.event.FocusListener {
		@Override
		default void focusGained(FocusEvent e) {
		}

		@Override
		default void focusLost(FocusEvent e) {
		}
	}

	interface KeyListener extends java.awt.event.KeyListener {
		@Override
		default void keyPressed(KeyEvent e) {
		}

		@Override
		default void keyReleased(KeyEvent e) {
		}

		@Override
		default void keyTyped(KeyEvent e) {
		}
	}

	interface MouseListener extends java.awt.event.MouseListener {
		@Override
		default void mouseClicked(MouseEvent e) {
		}

		@Override
		default void mouseEntered(MouseEvent e) {
		}

		@Override
		default void mouseExited(MouseEvent e) {
		}

		@Override
		default void mousePressed(MouseEvent e) {
		}

		@Override
		default void mouseReleased(MouseEvent e) {
		}
	}

	interface TreeExpansionListener extends javax.swing.event.TreeExpansionListener {
		@Override
		default void treeCollapsed(TreeExpansionEvent event) {
		}

		@Override
		default void treeExpanded(TreeExpansionEvent event) {
		}
	}
}
