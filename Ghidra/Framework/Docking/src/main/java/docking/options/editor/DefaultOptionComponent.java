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
package docking.options.editor;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.framework.options.EditorState;
import ghidra.util.HTMLUtilities;
import ghidra.util.layout.PairLayout;

public class DefaultOptionComponent extends GenericOptionsComponent {
	private JLabel label;
	private Component component;

	public DefaultOptionComponent(EditorState editorState) {
		super(editorState);
		setLayout(new PairLayout(0, 6, 40));
		this.component = editorState.getEditorComponent();

		label = new GDLabel(editorState.getTitle(), SwingConstants.RIGHT);

		if (component instanceof AbstractButton) {
			label.addMouseListener(new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent evt) {
					if (!component.isEnabled()) {
						return;
					}
					AbstractButton button = (AbstractButton) component;
					button.setSelected(!button.isSelected());
				}
			});
		}
		setSize(getPreferredSize());

		String description = editorState.getDescription();
		if (description != null) {
			String htmlDescription = HTMLUtilities.toWrappedHTML(description);
			label.setToolTipText(htmlDescription);
			if (component instanceof JComponent) {
				((JComponent) component).setToolTipText(htmlDescription);
			}
		}
		add(label);
		add(component);
	}

	@Override
	public void setEnabled(boolean enabled) {
		label.setEnabled(enabled);
		component.setEnabled(enabled);
	}

	@Override
	protected void setAlignmentPreferredSize(Dimension dimension) {
		label.setPreferredSize(dimension);
	}

	@Override // overridden to get the size based upon this class's two components
	protected Dimension getPreferredAlignmentSize() {
		Dimension dimension = label.getPreferredSize();
		int maxHeight = Math.max(dimension.height, component.getPreferredSize().height);
		return new Dimension(dimension.width, maxHeight);
	}
}
