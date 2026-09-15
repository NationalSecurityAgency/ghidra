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
package ghidra.app.merge.structures;

import java.awt.*;
import java.awt.event.MouseEvent;

import javax.swing.*;
import javax.swing.event.ChangeEvent;

import docking.*;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.button.GRadioButton;
import ghidra.app.merge.structures.CoordinatedStructureLine.CompareId;
import ghidra.program.model.data.Structure;
import ghidra.util.HelpLocation;
import ghidra.util.MessageType;
import utility.function.ExceptionalConsumer;

/**
 * Dialog for merging structures. The dialog is constructed given two structures and it will 
 * merge them, producing a third merged structure. The dialog will then display all three
 * structures and provide controls for dealing with conflicts, allowing the user to choose
 * components from the left or right side structures.
 * <P>
 * The dialog itself doesn't do anything with the resulting merged structure. Clients need
 * to provide an apply consumer that will be called when the user presses the dialog's apply
 * button.
 * <P>
 * The dialog also provides the following actions as keyboard only actions:
 * <OL>
 * 	<LI>Apply Item (&LT;SPACE&GT;): pressing the space bar key will apply the currently focussed and
 *  selected item from either the left side or right sided. (Assuming it is applicable).</LI>
 *  <LI>Focus Left Side (&LT;LEFT ARROW&GT;): pressing the left arrow will give focus to the left side
 *  display.</LI>
 *  <LI>Focus Right Side (&LT;RIGHT ARROW&GT;): pressing the right arrow will give focus to the right side
 *  display.</LI>
 * </OL>
 */
public class StructureMergeDialog extends DialogComponentProvider {
	private CoordinatedStructureModel model;
	private CoordinatedStructureDisplay mergedDisplay;
	private CoordinatedStructureDisplay leftDisplay;
	private CoordinatedStructureDisplay rightDisplay;
	private LeftRightButtonPanel leftRightChooserPanel;
	private DisplayCoordinator coordinator;
	private ExceptionalConsumer<Structure, Exception> applyConsumer;

	/**
	 * Constructor
	 * @param title the dialog title.
	 * @param struct1 the first structure (will receive precedence for any conflicting components
	 * @param struct2 the second structure
	 * @param applyConsumer the consumer to call when the user presses the apply button. This
	 * consumer can throw an exception which will be displayed in the dialog and the dialog won't
	 * close. If the apply does not throw an exception, the dialog will be closed.
	 */
	public StructureMergeDialog(String title, Structure struct1, Structure struct2,
			ExceptionalConsumer<Structure, Exception> applyConsumer) {
		super(title);
		this.applyConsumer = applyConsumer;
		setHelpLocation(new HelpLocation("DataTypeManagerPlugin", "MergeStructures"));

		model = new CoordinatedStructureModel(struct1, struct2, msg -> handleError(msg));

		buildDisplays();
		addWorkPanel(buildMainPanel());
		addActions();

		addApplyButton();
		addCancelButton();
		rootPanel.setFocusCycleRoot(true);
		rootPanel.setFocusTraversalPolicy(new StructureMergeDialogFocusTraveralPolicy());
	}

	private void addActions() {
		DockingAction applyAction = new ActionBuilder("Apply", getClass().getSimpleName())
				.keyBinding("SPACE")
				.description("Applies the selected structure component to the merged structure.")
				.withContext(StructureMergeDialogContext.class)
				.onAction(c -> toggleApply(c.getComparisonItem()))
				.build();
		addAction(applyAction);

		DockingAction goToLeftAction =
			new ActionBuilder("Left Display Action", getClass().getSimpleName())
					.keyBinding("LEFT")
					.description(
						"Give keyboard focus to left side view in structure merger dialog.")
					.onAction(c -> leftDisplay.getList().requestFocus())
					.build();
		addAction(goToLeftAction);
		DockingAction goToRightAction =
			new ActionBuilder("Right Display Action", getClass().getSimpleName())
					.keyBinding("RIGHT")
					.description(
						"Give keyboard focus to right side view in structure merger dialog.")
					.onAction(c -> rightDisplay.getList().requestFocus())
					.build();
		addAction(goToRightAction);

	}

	private void toggleApply(ComparisonItem item) {
		if (item == null) {
			return;
		}
		if (item.canApplyAny()) {
			item.applyAll();
		}
		else if (item.canClear()) {
			item.clear();
		}
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Component c = getComponent();
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Component focusedComponent = kfm.getFocusOwner();
		if (focusedComponent != null && SwingUtilities.isDescendingFrom(focusedComponent, c)) {
			c = focusedComponent;
		}

		if (event != null) {
			Component sourceComponent = event.getComponent();
			if (sourceComponent != null) {
				c = sourceComponent;
			}
		}

		CoordinatedStructureDisplay display = findDisplayForComponent(c);
		return new StructureMergeDialogContext(this, c, display);
	}

	private CoordinatedStructureDisplay findDisplayForComponent(Component c) {

		if (SwingUtilities.isDescendingFrom(c, leftDisplay)) {
			return leftDisplay;
		}
		if (SwingUtilities.isDescendingFrom(c, rightDisplay)) {
			return rightDisplay;
		}
		if (SwingUtilities.isDescendingFrom(c, leftDisplay)) {
			return mergedDisplay;
		}
		return null;
	}

	@Override
	protected void applyCallback() {
		try {
			applyConsumer.accept(model.getMergedStructure());
			close();
		}
		catch (Exception e) {
			setStatusText("Apply Failed: " + e.getMessage(), MessageType.ERROR);
		}
	}

	private void handleError(String errorMsg) {
		setStatusText(errorMsg);
	}

	private void buildDisplays() {
		coordinator = new DisplayCoordinator();
		leftDisplay = new CoordinatedStructureDisplay("Struct 1",
			new StructDisplayModel(model, CompareId.LEFT), coordinator);
		rightDisplay = new CoordinatedStructureDisplay("Struct 2",
			new StructDisplayModel(model, CompareId.RIGHT), coordinator);
		mergedDisplay = new CoordinatedStructureDisplay("Merged",
			new StructDisplayModel(model, CompareId.MERGED), coordinator);
		leftRightChooserPanel = new LeftRightButtonPanel();
		int rowHeight = Math.max(leftDisplay.getRowHeight(), leftRightChooserPanel.getRowHeight());
		leftRightChooserPanel.setRowHeight(rowHeight);
		leftDisplay.setRowHeight(rowHeight);
		rightDisplay.setRowHeight(rowHeight);
		mergedDisplay.setRowHeight(rowHeight);
	}

	private JComponent buildMainPanel() {
		JPanel panel = new JPanel(new GridLayout(2, 1, 10, 10));
		panel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		panel.add(buildSourcePanel());
		panel.add(mergedDisplay);
		return panel;
	}

	/**
	 * Customized focus traversal policy to avoid traversing to any of the apply buttons. The
	 * focus will go as follows: left display, right display, merged display, apply button, and
	 * finally cancel button.
	 */
	private class StructureMergeDialogFocusTraveralPolicy extends FocusTraversalPolicy {

		@Override
		public Component getComponentAfter(Container aContainer, Component aComponent) {
			if (SwingUtilities.isDescendingFrom(aComponent, leftDisplay)) {
				return rightDisplay.getList();
			}
			if (SwingUtilities.isDescendingFrom(aComponent, rightDisplay)) {
				return mergedDisplay.getList();
			}
			if (SwingUtilities.isDescendingFrom(aComponent, mergedDisplay)) {
				return applyButton;
			}
			if (aComponent == applyButton) {
				return cancelButton;
			}
			return leftDisplay.getList();

		}

		@Override
		public Component getComponentBefore(Container aContainer, Component aComponent) {
			if (aComponent == cancelButton) {
				return applyButton;
			}
			if (aComponent == applyButton) {
				return mergedDisplay.getList();
			}
			if (SwingUtilities.isDescendingFrom(aComponent, mergedDisplay)) {
				return rightDisplay.getList();
			}
			if (SwingUtilities.isDescendingFrom(aComponent, rightDisplay)) {
				return leftDisplay.getList();
			}
			return cancelButton;
		}

		@Override
		public Component getFirstComponent(Container aContainer) {
			return leftDisplay.getList();
		}

		@Override
		public Component getLastComponent(Container aContainer) {
			return cancelButton;
		}

		@Override
		public Component getDefaultComponent(Container aContainer) {
			return leftDisplay.getList();
		}

	}

	private Component buildSourcePanel() {
		// Using grid bag layout so that the two structure displays on either side of the 
		// button panel get all the available extra space. The middle button panel is always
		// fixed width.

		JPanel panel = new JPanel(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.gridx = 0;
		gbc.gridy = 0;
		gbc.gridwidth = 1;
		gbc.gridheight = 1;
		gbc.fill = GridBagConstraints.BOTH;
		gbc.weightx = 0.5;
		gbc.weighty = 1;
		panel.add(leftDisplay, gbc);

		gbc.gridx = 2;
		panel.add(rightDisplay, gbc);

		gbc.gridx = 1;
		gbc.weightx = 0.0;
		panel.add(leftRightChooserPanel, gbc);

		return panel;
	}

	private class LeftRightButtonPanel extends JPanel {
		private static int BUTTON_GAP = 7;
		private int rowHeight;
		private int buttonWidth;
		private int buttonHeight;
		private JPanel radioButtonPanel;
		private JViewport buttonPanelViewport;

		LeftRightButtonPanel() {
			super(new BorderLayout());
			Insets insets = leftDisplay.getInsets();
			setBorder(BorderFactory.createEmptyBorder(insets.top, 1, insets.bottom, 1));
			GRadioButton button = new GRadioButton();
			Dimension preferredButtonSize = button.getPreferredSize();
			rowHeight = preferredButtonSize.height;
			buttonHeight = preferredButtonSize.height;
			buttonWidth = preferredButtonSize.width;
			radioButtonPanel = new JPanel(null);

			// we need to set the preferred size of our inner panel to be at least as big as the
			// the corresponding coordinatedStructureViews or the scrolling doesn't work correctly.
			// if it is smaller, it limits the scroll position to its preferred size.
			radioButtonPanel.setPreferredSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
			buttonPanelViewport = new JViewport();
			buttonPanelViewport.setView(radioButtonPanel);
			add(buttonPanelViewport, BorderLayout.CENTER);
			leftDisplay.addViewportListener(e -> viewportChanged(e));
			model.addChangeListener(() -> buildButtons());
		}

		private void viewportChanged(ChangeEvent e) {
			JViewport viewport = (JViewport) e.getSource();
			buttonPanelViewport.setViewSize(viewport.getViewSize());
			buttonPanelViewport.setViewPosition(new Point(0, viewport.getViewPosition().y));
			buildButtons();
		}

		int getRowHeight() {
			return rowHeight;
		}

		void setRowHeight(int rowHeight) {
			this.rowHeight = rowHeight;
		}

		@Override
		public Dimension getPreferredSize() {
			Insets insets = getInsets();
			return new Dimension(2 * buttonWidth + BUTTON_GAP + insets.left + insets.right, 0);
		}

		@Override
		public Dimension getMinimumSize() {
			return getPreferredSize();
		}

		private void buildButtons() {
			int index1 = leftDisplay.getFirstVisibleIndex();
			int index2 = leftDisplay.getLastVisibleIndex();
			buildButtons(index1, index2);
			repaint();
		}

		public void buildButtons(int firstIndex, int lastIndex) {
			if (firstIndex < 0) {
				return;
			}
			radioButtonPanel.removeAll();

			for (int i = firstIndex; i <= lastIndex; i++) {
				int y = i * rowHeight + CoordinatedStructureDisplay.MARGIN;
				ComparisonItem leftItem = leftDisplay.getItem(i);
				ComparisonItem rightItem = rightDisplay.getItem(i);
				if (leftItem.isAppliable()) {
					buildButton(0, y, leftItem, true);
				}
				if (rightItem.isAppliable()) {
					buildButton(buttonWidth + BUTTON_GAP, y, rightItem, false);
				}
			}
		}

		private void buildButton(int x, int y, ComparisonItem item, boolean isLeft) {
			GRadioButton button = new GRadioButton();
			button.setBounds(x, y, buttonWidth, buttonHeight);
			button.setSelected(!item.canApplyAny());
			button.addActionListener(e -> {
				if (!button.isSelected() && !item.canClear()) {
					button.setSelected(true);
					return;
				}
				coordinator.setChanging(true);
				try {
					if (button.isSelected()) {
						item.applyAll();
					}
					else {
						item.clear();
					}

					// We need to validate the mergedDisplay with the coordinator disabled.
					// Otherwise, it will revalidate on the next repaint which may cause it to 
					// resize, which in turn will move its viewport, which then affects the source
					// panel, causing them to jump as buttons are pressed.
					mergedDisplay.validate();
					CoordinatedStructureDisplay focusDisplay = isLeft ? leftDisplay : rightDisplay;
					focusDisplay.getList().requestFocus();
				}
				finally {
					coordinator.setChanging(false);
				}
			});
			radioButtonPanel.add(button);
		}

	}

	private class StructureMergeDialogContext extends DefaultActionContext {

		private CoordinatedStructureDisplay display;

		public StructureMergeDialogContext(DialogComponentProvider dialog, Component source,
				CoordinatedStructureDisplay display) {
			super(null, dialog, source);
			this.display = display;
		}

		public ComparisonItem getComparisonItem() {
			return display != null ? display.getSelectedItem() : null;
		}
	}

}
