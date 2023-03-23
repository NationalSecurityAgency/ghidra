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

import java.awt.Color;

import javax.swing.*;
import javax.swing.tree.TreeCellRenderer;

public interface ColorsModified<P extends JComponent> {

	Color getDiffForeground(P p);

	Color getDiffSelForeground(P p);

	Color getForeground(P p);

	Color getSelForeground(P p);

	default Color getForegroundFor(P p, boolean isModified, boolean isSelected) {
		return isModified ? isSelected ? getDiffSelForeground(p) : getDiffForeground(p)
				: isSelected ? getSelForeground(p) : getForeground(p);
	}

	interface InTable extends ColorsModified<JTable> {
		@Override
		default Color getForeground(JTable table) {
			return table.getForeground();
		}

		@Override
		default Color getSelForeground(JTable table) {
			return table.getSelectionForeground();
		}
	}

	interface InTree extends ColorsModified<JTree>, TreeCellRenderer {

		Color getTextNonSelectionColor();

		Color getTextSelectionColor();

		@Override
		default Color getForeground(JTree tree) {
			return getTextNonSelectionColor();
		}

		@Override
		default Color getSelForeground(JTree tree) {
			return getTextSelectionColor();
		}
	}
}
