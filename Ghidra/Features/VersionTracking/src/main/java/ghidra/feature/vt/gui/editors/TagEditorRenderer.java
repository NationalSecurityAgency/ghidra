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
package ghidra.feature.vt.gui.editors;

import static ghidra.feature.vt.gui.editors.TagEditorDialog.TagState.Action.ADD;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import docking.widgets.list.GListCellRenderer;
import ghidra.feature.vt.gui.editors.TagEditorDialog.TagState;
import ghidra.feature.vt.gui.editors.TagEditorDialog.TagStateListModel;
import ghidra.util.exception.AssertException;
import resources.ResourceManager;

public class TagEditorRenderer extends GListCellRenderer<TagState> {

	private static final Icon NEW_TAG_ICON = ResourceManager.loadImage("images/tag_blue_add.png");
	private static final Icon DELETED_TAG_ICON =
		ResourceManager.loadImage("images/tag_blue_delete.png");
	private static final Icon EXISTING_TAG_ICON = ResourceManager.loadImage("images/tag_blue.png");
	private static final Icon UNDO_ICON = ResourceManager.loadImage("images/undo-apply.png");

	private final JList<TagState> list;
	private final TagStateListModel listModel;

	private JPanel panel;
	private JLabel tagIconLabel = new GDLabel();
	private RemoveStateButton undoButton;
	private MouseAdapter mouseForwarder;

	TagEditorRenderer(JList<TagState> list, TagStateListModel listModel) {
		this.list = list;
		this.listModel = listModel;

		mouseForwarder = new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component hoveredComponent =
					SwingUtilities.getDeepestComponentAt(event.getComponent(), x, y);
				if (hoveredComponent == null) {
					return;
				}

				updateButton(hoveredComponent, true);
				list.repaint();
			}

			@Override
			public void mouseExited(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component hoveredComponent =
					SwingUtilities.getDeepestComponentAt(event.getComponent(), x, y);
				updateButton(hoveredComponent, false);
				list.repaint();
			}

			@Override
			public void mousePressed(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component componentSource = event.getComponent();
				Component clickedComponent =
					SwingUtilities.getDeepestComponentAt(componentSource, x, y);
				if (clickedComponent == null) {
					return;
				}

				updateButton(clickedComponent, true);
				list.repaint();
			}

			@Override
			public void mouseReleased(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component componentSource = event.getComponent();
				Component clickedComponent =
					SwingUtilities.getDeepestComponentAt(componentSource, x, y);
				if (clickedComponent == null) {
					return;
				}

				updateButton(clickedComponent, false);
				list.repaint();
			}

			@Override
			public void mouseClicked(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component componentSource = event.getComponent();

				Component clickedComponent =
					SwingUtilities.getDeepestComponentAt(componentSource, x, y);
				if (clickedComponent == null || componentSource == clickedComponent) {
					return;
				}

				MouseEvent newEvent =
					new MouseEvent(clickedComponent, event.getID(), event.getWhen(),
						event.getModifiers(), x, y, event.getXOnScreen(), event.getYOnScreen(),
						event.getClickCount(), event.isPopupTrigger(), event.getButton());

				clickedComponent.dispatchEvent(newEvent);
				list.repaint();
			}

			@Override
			public void mouseMoved(MouseEvent event) {
				int x = event.getX();
				int y = event.getY();
				Component hoveredComponent =
					SwingUtilities.getDeepestComponentAt(event.getComponent(), x, y);
				if (hoveredComponent == null) {
					return;
				}

				updateButton(hoveredComponent, false);
				list.repaint();
			}

			public void updateButton(Component mousedComponent, boolean pressed) {
				Component component = mousedComponent;
				if (component == undoButton) {
					undoButton.getTagState().setMousePressed(pressed);
					list.repaint();
				}

				if (component == null) {
					undoButton.getTagState().setMousePressed(false);
					list.repaint();
				}
			}

		};
	}

	@Override
	protected String getItemText(TagState value) {
		return value.getTagName();
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends TagState> jList, TagState state,
			int index, boolean isSelected, boolean cellHasFocus) {
		JLabel renderer = (JLabel) super.getListCellRendererComponent(jList, state, index,
			isSelected, cellHasFocus);

		initializePanel(renderer);

		tagIconLabel.setIcon(getIcon(state));

		if (!isSelected) {
			state.setMousePressed(false);
		}

		panel.remove(undoButton);
		if (!state.isUnmodified()) {
			panel.add(undoButton);
			panel.validate();
		}

		undoButton.setTagState(state);

		return panel;
	}

	private Icon getIcon(TagState tagState) {
		switch (tagState.getAction()) {
			case ADD:
				return NEW_TAG_ICON;
			case DELETE:
				return DELETED_TAG_ICON;
			case UNMODIFIED:
				return EXISTING_TAG_ICON;
		}
		throw new AssertException("Unexpected tag action: " + tagState.getAction());
	}

	private JPanel initializePanel(JLabel renderer) {
		if (panel == null) {
			JScrollPane scrollPane = new JScrollPane();
			panel = new JPanel() {
				@Override
				public String getToolTipText(MouseEvent event) {
					int x = event.getX();
					int y = event.getY();

					Rectangle bounds = undoButton.getBounds();
					if ((x >= bounds.x && x <= bounds.x + bounds.width) &&
						(y >= bounds.y && y <= bounds.y + bounds.height)) {
						return undoButton.getToolTipText();
					}

					return super.getToolTipText();
				}
			};

			undoButton = new RemoveStateButton();
			undoButton.setBackground(list.getBackground());

			// let our color match that of the scroll pane our list is inside of
			panel.setBackground(scrollPane.getBackground());

			panel.setLayout(new BoxLayout(panel, BoxLayout.X_AXIS));
			panel.add(tagIconLabel);
			panel.add(Box.createHorizontalStrut(5));
			panel.add(renderer);
			panel.add(Box.createHorizontalGlue());
			panel.add(Box.createRigidArea(new Dimension(0, 20))); // make sure we are big enough for our button's height
			panel.add(undoButton);

			panel.addMouseListener(mouseForwarder);
			panel.addMouseMotionListener(mouseForwarder);
		}
		return panel;
	}

	private class RemoveStateButton extends JButton {

		private TagState state;

		RemoveStateButton() {
			super(UNDO_ICON);

			putClientProperty("JButton.buttonType", "segmentedRoundRect");
			putClientProperty("JButton.segmentPosition", "only");

			addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					TagState.Action action = state.getAction();
					if (action == ADD) {
						listModel.removeElement(state);
					}
					else {
						state.restoreState();
					}

					list.repaint();

				}
			});
		}

		private void setPressed(boolean hovered) {
			undoButton.getModel().setArmed(hovered);
			undoButton.getModel().setPressed(hovered);
		}

		void setTagState(TagState state) {
			this.state = state;
			TagState.Action action = state.getAction();
			if (action == ADD) {
				setToolTipText("Remove this newly added tag");
			}
			else {
				setToolTipText("Undo mark for deletion");
			}

			setPressed(state.isMousePressed());
		}

		TagState getTagState() {
			return state;
		}
	}
}
