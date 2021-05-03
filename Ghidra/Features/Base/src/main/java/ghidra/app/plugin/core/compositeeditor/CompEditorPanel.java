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
package ghidra.app.plugin.core.compositeeditor;

import java.awt.*;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import docking.widgets.OptionDialog;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitAttributes;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.Composite.AlignmentType;
import ghidra.util.HelpLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for editing a composite with a blank line at the bottom of the table
 * when in unlocked mode.
 */
public class CompEditorPanel extends CompositeEditorPanel {

	private final static String NO_PACKING_STRING = "";
	protected final static Insets LEFT_INSETS = new Insets(2, 3, 1, 0);
	protected final static Insets VERTICAL_INSETS = new Insets(2, 0, 1, 0);

	// GUI components for displaying composite data type information.
	protected GridBagLayout gridBagLayout;
	protected JPanel infoPanel;
	protected JLabel nameLabel;
	protected JTextField nameTextField;
	protected JLabel descriptionLabel;
	protected JTextField descriptionTextField;
	protected JLabel categoryLabel;
	protected JTextField categoryStatusTextField;
	protected JLabel sizeLabel;
	protected JTextField sizeStatusTextField;

	protected JCheckBox internalAlignmentCheckBox;

	protected JPanel minimumAlignmentPanel;
	protected JRadioButton defaultMinAlignButton;
	protected JRadioButton machineMinAlignButton;
	protected JRadioButton byValueMinAlignButton;
	protected JTextField minAlignValueTextField;

	protected JPanel packingPanel;
	protected JRadioButton noPackingButton;
	protected JRadioButton byValuePackingButton;
	protected JTextField packingValueTextField;

	protected JLabel actualAlignmentLabel;
	protected JTextField actualAlignmentValueTextField;

	private BitFieldPlacementComponent bitViewComponent;

	private DocumentListener fieldDocListener;

	private ActionListener fieldActionListener;

	private FocusListener fieldFocusListener;

	private boolean updatingSize;

	/**
	 * Constructor for a panel that has a blank line in unlocked mode and
	 * composite name and description that are editable.
	 * 
	 * @param model
	 *            the model for editing the composite data type
	 * @param provider
	 *            the editor provider furnishing this panel for editing.
	 */
	public CompEditorPanel(CompEditorModel model, CompositeEditorProvider provider) {
		super(model, provider);
		setInternallyAligned(model.viewComposite.isInternallyAligned());
	}

	@Override
	public void dispose() {
		removeFieldListeners();
		super.dispose();
	}

	@Override
	public void componentDataChanged() {
		refreshGUIActualAlignmentValue();
		setCompositeSize(model.getLength());
	}

	@Override
	public void compositeInfoChanged() {
		adjustCompositeInfo();
		if (model.showHexNumbers != bitViewComponent.isShowOffsetsInHex()) {
			bitViewComponent.setShowOffsetsInHex(model.showHexNumbers);
		}
	}

	/**
	 * Updates the name, description, etc. that appears below the table.
	 */
	@Override
	protected void adjustCompositeInfo() {
		setCompositeName(model.getCompositeName());
		setDescription(model.getDescription());
		Category c = model.getOriginalCategory();
		if (c != null) {
			setCategoryName(c.toString());
		}
		setInternallyAligned(((CompEditorModel) model).isAligned());
		refreshGUIMinimumAlignmentType();
		refreshGUIMinimumAlignmentValue();
		refreshGUIActualAlignmentValue();
		setCompositeSize(model.getLength());
		refreshGUIPackingValue();
	}

	private void refreshGUIMinimumAlignmentType() {
		AlignmentType minimumAlignmentType = ((CompEditorModel) model).getMinimumAlignmentType();
		if (minimumAlignmentType == AlignmentType.DEFAULT_ALIGNED) {
			defaultMinAlignButton.setSelected(true);
		}
		else if (minimumAlignmentType == AlignmentType.MACHINE_ALIGNED) {
			machineMinAlignButton.setSelected(true);
		}
		else {
			byValueMinAlignButton.setSelected(true);
		}
	}

	@Override
	protected JPanel createBitViewerPanel() {

		bitViewComponent = new BitFieldPlacementComponent(model.viewComposite, false);
		bitViewComponent.setShowOffsetsInHex(model.showHexNumbers);
		model.addCompositeViewerModelListener(new CompositeEditorModelAdapter() {
			@Override
			public void selectionChanged() {
				update(false);
			}

			@Override
			public void componentDataChanged() {
				update(true);
			}

			private void update(boolean dataChanged) {
				if (!model.isLoaded()) {
					bitViewComponent.setComposite(null);
					return;
				}
				if (bitViewComponent.getComposite() != model.viewComposite) {
					// must track instance changes caused by model unload/load invocations
					bitViewComponent.setComposite(model.viewComposite);
				}

				int length = model.viewComposite.getLength();
				if (length != bitViewComponent.getAllocationByteSize()) {
					bitViewComponent.updateAllocation(length, 0);
				}

				DataTypeComponent dtc = null;
				if (model.isSingleComponentRowSelection()) {
					dtc = model.getComponent(model.getSelectedRows()[0]);
				}

				Rectangle selectedRectangle = bitViewComponent.getComponentRectangle(dtc);
				if (selectedRectangle != null) {
					bitViewComponent.scrollRectToVisible(selectedRectangle);
					validate();
				}

				bitViewComponent.init(dtc);

			}
		});

		bitViewComponent.addMouseListener(new MouseAdapter() {

			@Override
			public void mousePressed(MouseEvent e) {
				Point p = e.getPoint();
				BitAttributes attrs = bitViewComponent.getBitAttributes(p);
				if (attrs == null) {
					return;
				}
				DataTypeComponent dtc = attrs.getDataTypeComponent(false);
				if (dtc != null) {
					model.setSelection(new int[] { dtc.getOrdinal() });
					table.scrollToSelectedRow();
				}
				else {
					model.setSelection(new FieldSelection());
				}
			}
		});

		JPanel bitViewPanel = new JPanel(new PairLayout(0, 5));

		JPanel labelPanel = new JPanel(new VerticalLayout(7));
		labelPanel.setBorder(BorderFactory.createEmptyBorder(7, 5, 0, 0));
		JLabel byteOffsetLabel = new JLabel("Byte Offset:", SwingConstants.RIGHT);
		labelPanel.add(byteOffsetLabel);
		labelPanel.add(new JLabel("Component Bits:", SwingConstants.RIGHT));
		bitViewPanel.add(labelPanel);

		JScrollPane bitViewScrollPane =
			new JScrollPane(bitViewComponent, ScrollPaneConstants.VERTICAL_SCROLLBAR_NEVER,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);

		bitViewScrollPane.getViewport().setBackground(getBackground());
		bitViewScrollPane.setBorder(null);

		// establish default preferred size of panel based upon fixed preferred height of bitViewComponent
		Dimension bitViewerDefaultSize = new Dimension(800, bitViewComponent.getPreferredHeight());
		bitViewScrollPane.setPreferredSize(bitViewerDefaultSize);

		bitViewPanel.add(bitViewScrollPane);
		return bitViewPanel;
	}

	/**
	 * Create the Info Panel that is horizontally resizable. The panel contains
	 * the name, category, data type, size, and edit mode for the current
	 * structure in the editor.
	 * 
	 * @return JPanel the completed composite data type information panel
	 */
	@Override
	protected JPanel createInfoPanel() {

		gridBagLayout = new GridBagLayout();
		infoPanel = new JPanel(gridBagLayout);

		this.setBorder(BEVELED_BORDER);

		setupName();
		setupDescription();
		setupCategory();
		setupSize();
		setupActualAlignment();
		setupInternallyAligned();
		setupMinimumAlignment();
		setupPacking();

		addFieldListeners();

		infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		return infoPanel;
	}

	private void setupName() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		nameLabel = new GDLabel("Name:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		infoPanel.add(nameLabel, gridBagConstraints);

		nameTextField = new JTextField("");
		nameTextField.setToolTipText("Structure Name");
		nameTextField.setEditable(true);
		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(nameTextField, gridBagConstraints);

		if (helpManager != null) {
			helpManager.registerHelp(nameTextField,
				new HelpLocation(provider.getHelpTopic(), provider.getHelpName() + "_" + "Name"));
		}
	}

	private void setupDescription() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		descriptionLabel = new GDLabel("Description:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		infoPanel.add(descriptionLabel, gridBagConstraints);

		descriptionTextField = new JTextField("");
		descriptionTextField.setToolTipText("Structure Description");
		descriptionTextField.setEditable(true);
		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(descriptionTextField, gridBagConstraints);

		if (helpManager != null) {
			helpManager.registerHelp(descriptionTextField, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "Description"));
		}
	}

	private void setupCategory() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		categoryLabel = new GDLabel("Category:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 2;
		infoPanel.add(categoryLabel, gridBagConstraints);

		categoryStatusTextField = new JTextField(" ");
		categoryStatusTextField.setEditable(false);
		categoryStatusTextField.setToolTipText("Category of this composite data type.");
		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(categoryStatusTextField, gridBagConstraints);
	}

	private void setupInternallyAligned() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		internalAlignmentCheckBox = new GCheckBox("Align");
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 4;
		gridBagConstraints.gridy = 3;
		internalAlignmentCheckBox.setSelected(model.viewComposite.isInternallyAligned());
		internalAlignmentCheckBox.setToolTipText(
			"Whether or not the internal components of this structure are aligned.");
		internalAlignmentCheckBox.setEnabled(true);
		if (helpManager != null) {
			helpManager.registerHelp(internalAlignmentCheckBox, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "InternallyAligned"));
		}
		internalAlignmentCheckBox.setName("Internally Aligned");

		internalAlignmentCheckBox.addItemListener(e -> adjustInternalAlignment());
		infoPanel.add(internalAlignmentCheckBox, gridBagConstraints);
	}

	protected void adjustInternalAlignment() {
		boolean aligned = internalAlignmentCheckBox.isSelected();
		((CompEditorModel) model).setAligned(aligned);
		if (aligned) {
			showMinimumAlignment();
		}
		else {
			hideMinimumAlignment();
		}
		packingValueTextField.setEditable(aligned);
		if (aligned) {
			showPacking();
		}
		else {
			hidePacking();
		}
	}

	@Override
	public Dimension getPreferredSize() {
		// make sure our preferred size accounts for that of our components that the user 
		// may choose to show 
		Dimension preferredSize = super.getPreferredSize();
		if (minimumAlignmentPanel.isShowing()) {
			return preferredSize;
		}

		Dimension alignmentPanelPreferredSize = minimumAlignmentPanel.getPreferredSize();
		preferredSize.width += alignmentPanelPreferredSize.width;

		Dimension packingPanelPreferredSize = packingPanel.getPreferredSize();
		preferredSize.width += packingPanelPreferredSize.width;

		return preferredSize;
	}

	private void setupMinimumAlignment() {
		defaultMinAlignButton = new GRadioButton("none           ");
		machineMinAlignButton = new GRadioButton("machine      ");
		byValueMinAlignButton = new GRadioButton();
		minAlignValueTextField = new JTextField();
		setupDefaultMinAlignButton();
		setupMachineMinAlignButton();
		setupByValueMinAlignButton();
		ButtonGroup minAlignGroup = new ButtonGroup();
		minAlignGroup.add(defaultMinAlignButton);
		minAlignGroup.add(machineMinAlignButton);
		minAlignGroup.add(byValueMinAlignButton);
		refreshGUIMinimumAlignmentType();

		minimumAlignmentPanel = new JPanel(new GridBagLayout());
		minimumAlignmentPanel.setBorder(BorderFactory.createTitledBorder("align( minimum )"));
		if (helpManager != null) {
			helpManager.registerHelp(minimumAlignmentPanel, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "AlignMinimum"));
		}
		String alignmentToolTip = "<HTML>" + "The minimum alignment to be used when<BR>" +
			"aligning this data type inside another data type.<BR><BR>" +
			"Align this data type <BR>" +
			"... in the <B>default</B> way based only on its components with <B>no</B> minimum,<BR>" +
			"... to a multiple of the <B>machine</B> alignment,<BR>" +
			"... to a multiple of the <B>specified value</B> in the text field." + "</HTML>";
		minimumAlignmentPanel.setToolTipText(alignmentToolTip);

		addMinimumAlignmentComponents();
	}

	private void addMinimumAlignmentComponents() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 2;
		minimumAlignmentPanel.add(defaultMinAlignButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 2;
		minimumAlignmentPanel.add(machineMinAlignButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 1;
		minimumAlignmentPanel.add(byValueMinAlignButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 1;
		minimumAlignmentPanel.add(minAlignValueTextField, gridBagConstraints);
	}

	private void setupDefaultMinAlignButton() {
		defaultMinAlignButton.setName("Default Minimum Alignment");
		String alignmentToolTip =
			"<HTML>" + "Sets this data type to have <B>no</B> minimum alignment<BR>" +
				"when aligning this data type inside another data type.<BR>" +
				"Align this data type based only on its components." + "</HTML>";
		defaultMinAlignButton.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(defaultMinAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "AlignMinimum"));
		}
	}

	private void setupMachineMinAlignButton() {
		machineMinAlignButton.setName("Machine Minimum Alignment");
		String alignmentToolTip = "<HTML>" + "Sets this data type to have a minimum alignment<BR>" +
			"that is a multiple of the <B>machine</B> alignment<BR>" +
			"when aligning this data type inside another data type." + "</HTML>";
		machineMinAlignButton.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(machineMinAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "AlignMinimum"));
		}
	}

	private void setupByValueMinAlignButton() {
		byValueMinAlignButton.setName("By Value Minimum Alignment");
		String alignmentToolTip = "<HTML>" + "Sets this data type to have a minimum alignment<BR>" +
			"that is a multiple of the <B>specified value</B><BR>" +
			"when aligning this data type inside another data type." + "</HTML>";
		byValueMinAlignButton.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(byValueMinAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "AlignMinimum"));
		}

		minAlignValueTextField.setName("Minimum Alignment Value");
		minAlignValueTextField.setEditable(true);
		minAlignValueTextField.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(minAlignValueTextField, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "AlignMinimum"));
		}

		refreshGUIMinimumAlignmentValue(); // Display the initial value.
	}

	private void showMinimumAlignment() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 5;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridheight = 4;
		infoPanel.add(minimumAlignmentPanel, gridBagConstraints);
		infoPanel.invalidate();
		validate();
	}

	private void hideMinimumAlignment() {
		infoPanel.remove(minimumAlignmentPanel);
		infoPanel.invalidate();
		validate();
	}

	protected void adjustMinimumAlignmentValue() {
		String value = minAlignValueTextField.getText();
		try {
			int minAlignment = Integer.decode(value);
			try {
				((CompEditorModel) model).setAlignment(minAlignment);
				adjustCompositeInfo();
			}
			catch (InvalidInputException e1) {
				refreshGUIMinimumAlignmentValue();
				String message = "\"" + value + "\" is not a valid minimum alignment value.";
				setStatus(message);
			}
		}
		catch (NumberFormatException e1) {
			refreshGUIMinimumAlignmentValue();
			String message = "\"" + value + "\" is not a valid minimum alignment value.";
			setStatus(message);
		}
	}

	private void setupActualAlignment() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		String actualAlignmentToolTip = "<HTML>" + "The actual alignment to be used when<BR>" +
			"aligning this data type inside another data type." + "</HTML>";

		JPanel actualAlignmentPanel = new JPanel(new BorderLayout());
		actualAlignmentLabel = new GDLabel("Alignment:");
		gridBagConstraints.insets = new Insets(2, 7, 2, 2);
		gridBagConstraints.anchor = GridBagConstraints.EAST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 2;
		gridBagConstraints.gridy = 3;
		actualAlignmentLabel.setToolTipText(actualAlignmentToolTip);
		actualAlignmentPanel.add(actualAlignmentLabel, BorderLayout.EAST);
		infoPanel.add(actualAlignmentPanel, gridBagConstraints);

		actualAlignmentValueTextField = new JTextField(8);
		actualAlignmentValueTextField.setText("" + ((CompEditorModel) model).getMinimumAlignment());
		actualAlignmentValueTextField.setToolTipText(actualAlignmentToolTip);
		actualAlignmentValueTextField.setEditable(false);
		if (helpManager != null) {
			helpManager.registerHelp(actualAlignmentValueTextField, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "ActualAlignment"));
		}
		actualAlignmentValueTextField.setName("Actual Alignment Value");

		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.ipadx = 50;
		gridBagConstraints.gridx = 3;
		gridBagConstraints.gridy = 3;
		infoPanel.add(actualAlignmentValueTextField, gridBagConstraints);
	}

	private void setupPacking() {
		noPackingButton = new GRadioButton("none           ");
		byValuePackingButton = new GRadioButton();
		packingValueTextField = new JTextField();
		setupNoPackingButton();
		setupByValuePackingButton();

		ButtonGroup packingGroup = new ButtonGroup();
		packingGroup.add(noPackingButton);
		packingGroup.add(byValuePackingButton);

		packingPanel = new JPanel(new GridBagLayout());
		packingPanel.setBorder(BorderFactory.createTitledBorder("pack( maximum )"));
		if (helpManager != null) {
			helpManager.registerHelp(packingPanel, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "PackMaximum"));
		}
		String packingToolTipText =
			"<HTML>\"none\" indicates components are not being packed.<BR>" +
				"Otherwise, the value indicates the maximum alignment to use when packing any component.<BR>" +
				"Note: An individual data type's alignment may override this value.</HTML>";
		packingPanel.setToolTipText(packingToolTipText);

		addPackingComponents();
		refreshGUIPackingValue();
	}

	private void addPackingComponents() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 2;
		packingPanel.add(noPackingButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		packingPanel.add(byValuePackingButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		packingPanel.add(packingValueTextField, gridBagConstraints);
	}

	private void setupNoPackingButton() {
		noPackingButton.setName("No Packing");
		String packingToolTipText =
			"<HTML>\"none\" indicates components are not being packed.<BR>" +
				"Otherwise, the value indicates the maximum alignment to use when packing any component.<BR>" +
				"Note: An individual data type's alignment may override this value.</HTML>";

		noPackingButton.addActionListener(e -> {
			((CompEditorModel) model).setPackingValue(Composite.NOT_PACKING);
		});

		noPackingButton.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(noPackingButton, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "PackMaximum"));
		}
	}

	private void setupByValuePackingButton() {
		byValuePackingButton.setName("By Value Packing");
		String packingToolTipText =
			"<HTML>\"none\" indicates components are not being packed.<BR>" +
				"Otherwise, the value indicates the maximum alignment to use when packing any component.<BR>" +
				"Note: An individual data type's alignment may override this value.</HTML>";

		byValuePackingButton.addActionListener(e -> chooseByValuePacking());
		byValuePackingButton.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(byValuePackingButton, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "PackMaximum"));
		}

		packingValueTextField.setName("Packing Value");
		packingValueTextField.setEditable(true);

		packingValueTextField.addActionListener(e -> adjustPackingValue());

		packingValueTextField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				if (byValuePackingButton.isSelected()) {
					return;
				}
				byValuePackingButton.setSelected(true);
				chooseByValuePacking();
			}

			@Override
			public void focusLost(FocusEvent e) {
				adjustPackingValue();
			}
		});

		packingValueTextField.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(packingValueTextField, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "PackMaximum"));
		}
	}

	protected void chooseByValuePacking() {
		((CompEditorModel) model).setPackingValue(1);
		packingValueTextField.selectAll();
		packingValueTextField.requestFocus();
	}

	protected void adjustPackingValue() {
		if (!packingValueTextField.isShowing()) {
			return;
		}
		String value = packingValueTextField.getText();
		try {
			int packingAlignment = 0;
			if (!value.toLowerCase().equals(NO_PACKING_STRING)) {
				packingAlignment = Integer.decode(value);
			}

			((CompEditorModel) model).setPackingValue(packingAlignment);
			adjustCompositeInfo();
		}
		catch (NumberFormatException e1) {
			refreshGUIPackingValue();
			setStatus(value + " is not a valid packing value.");
		}
	}

	private void showPacking() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 7;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridheight = 4;
		infoPanel.add(packingPanel, gridBagConstraints);
		infoPanel.invalidate();
		validate();
	}

	private void hidePacking() {
		infoPanel.remove(packingPanel);
		infoPanel.invalidate();
		validate();
	}

	/**
	 * Sets the currently displayed structure packing value (maximum component alignment)
	 */
	public void refreshGUIPackingValue() {
		int packingValue = ((CompEditorModel) model).getPackingValue();
		boolean isPacking = (packingValue != Composite.NOT_PACKING);
		if (isPacking) {
			byValuePackingButton.setSelected(true);
		}
		else {
			noPackingButton.setSelected(true);
		}
		String packingString;
		if (isPacking) {
			packingString =
				model.showHexNumbers ? CompositeViewerModel.getHexString(packingValue, true)
						: Integer.toString(packingValue);
		}
		else {
			packingString = NO_PACKING_STRING;
		}
		packingValueTextField.setText(packingString);
	}

	protected void setupSize() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		sizeLabel = new GDLabel("Size:");
		sizeLabel.setToolTipText("The current size in bytes.");
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 3;
		infoPanel.add(sizeLabel, gridBagConstraints);

		sizeStatusTextField = new JTextField(10);
		sizeStatusTextField.setName("Total Length");
		sizeStatusTextField.setEditable(false);
		sizeStatusTextField.setToolTipText("The current size in bytes.");
		gridBagConstraints.ipadx = 60;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 3;
		infoPanel.add(sizeStatusTextField, gridBagConstraints);

		sizeStatusTextField.addActionListener(e -> updatedStructureSize());
		sizeStatusTextField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// don't care
			}

			@Override
			public void focusLost(FocusEvent e) {
				if (sizeStatusTextField.isEditable()) {
					updatedStructureSize();
				}
			}
		});
	}

	protected void setSizeEditable(boolean editable) {
		sizeStatusTextField.setEditable(editable);
	}

	private void updatedStructureSize() {

		if (updatingSize) {
			return;
		}
		if (!sizeStatusTextField.isShowing()) {
			return;
		}

		if (!((CompEditorModel) model).isSizeEditable()) {
			return;
		}

		String valueStr = sizeStatusTextField.getText();
		Integer value;
		try {
			updatingSize = true;
			value = Integer.decode(valueStr);
			int structureSize = value.intValue();
			if (structureSize < 0) {
				model.setStatus("Structure size cannot be negative.", true);
			}
			else {
				if (structureSize < model.getLength()) {
					// Decreasing structure length.
					// Verify that user really wants this.
					String question =
						"The size field was changed to " + structureSize + " bytes.\n" +
							"Do you really want to truncate " + model.getCompositeName() + "?";
					String title = "Truncate " + model.getTypeName() + " In Editor?";
					int response =
						OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, title, question);
					if (response != OptionDialog.YES_OPTION) {
						compositeInfoChanged();
						return;
					}
				}
				((StructureEditorModel) model).setStructureSize(structureSize);
			}
		}
		catch (NumberFormatException e1) {
			model.setStatus("Invalid structure size \"" + valueStr + "\".", true);
		}
		finally {
			updatingSize = false;
		}
		compositeInfoChanged();
	}

	private void addFieldListeners() {
		fieldDocListener = new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent e) {
				changed(e);
			}

			@Override
			public void removeUpdate(DocumentEvent e) {
				changed(e);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				changed(e);
			}

			private void changed(DocumentEvent e) {
				Document doc = e.getDocument();
				if (doc.equals(nameTextField.getDocument())) {
					model.clearStatus();
					String name = nameTextField.getText().trim();
					if (name.length() == 0) {
						return;
					}
					try {

						model.setName(name);
					}
					catch (DuplicateNameException dne) {
						model.setStatus("A data type named " + name + " already exists.");
					}
					catch (InvalidNameException ine) {
						model.setStatus(name + " is not a valid name.");
					}
				}
				else if (doc.equals(descriptionTextField.getDocument())) {
					model.clearStatus();
					model.setDescription(descriptionTextField.getText().trim());
				}
			}
		};
		nameTextField.getDocument().addDocumentListener(fieldDocListener);
		descriptionTextField.getDocument().addDocumentListener(fieldDocListener);

		// Set the description so it can be edited.
		fieldActionListener = e -> {
			Object source = e.getSource();
			if (source == nameTextField) {
				updatedName();
			}
			else if (source == descriptionTextField) {
				updatedDescription();
			}
			else if (source == defaultMinAlignButton) {
				chooseDefaultMinAlign();
			}
			else if (source == machineMinAlignButton) {
				chooseMachineMinAlign();
			}
			else if (source == byValueMinAlignButton) {
				chooseByValueMinAlign();
			}
			else if (source == minAlignValueTextField) {
				updatedMinAlignValue();
			}
		};
		nameTextField.addActionListener(fieldActionListener);
		descriptionTextField.addActionListener(fieldActionListener);
		defaultMinAlignButton.addActionListener(fieldActionListener);
		machineMinAlignButton.addActionListener(fieldActionListener);
		byValueMinAlignButton.addActionListener(fieldActionListener);
		minAlignValueTextField.addActionListener(fieldActionListener);

		fieldFocusListener = new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				Object source = e.getSource();
				if (source == minAlignValueTextField) {
					if (byValueMinAlignButton.isSelected()) {
						return;
					}
					byValueMinAlignButton.setSelected(true);
					chooseByValueMinAlign();
				}
			}

			@Override
			public void focusLost(FocusEvent e) {
				Object source = e.getSource();
				if (source == nameTextField) {
					updatedName();
				}
				else if (source == descriptionTextField) {
					updatedDescription();
				}
				else if (source == minAlignValueTextField) {
					updatedMinAlignValue();
				}
			}
		};
		nameTextField.addFocusListener(fieldFocusListener);
		descriptionTextField.addFocusListener(fieldFocusListener);
		minAlignValueTextField.addFocusListener(fieldFocusListener);

	}

	protected void chooseDefaultMinAlign() {
		((CompEditorModel) model).setAlignmentType(AlignmentType.DEFAULT_ALIGNED);
	}

	protected void chooseMachineMinAlign() {
		((CompEditorModel) model).setAlignmentType(AlignmentType.MACHINE_ALIGNED);
	}

	protected void chooseByValueMinAlign() {
		((CompEditorModel) model).setAlignmentType(AlignmentType.ALIGNED_BY_VALUE);
		minAlignValueTextField.selectAll();
		minAlignValueTextField.requestFocus();
	}

	protected void updatedMinAlignValue() {
		adjustMinimumAlignmentValue();
	}

	private void removeFieldListeners() {
		nameTextField.getDocument().removeDocumentListener(fieldDocListener);
		nameTextField.removeActionListener(fieldActionListener);
		nameTextField.removeFocusListener(fieldFocusListener);

		descriptionTextField.getDocument().removeDocumentListener(fieldDocListener);
		descriptionTextField.removeActionListener(fieldActionListener);
		descriptionTextField.removeFocusListener(fieldFocusListener);

		defaultMinAlignButton.addActionListener(fieldActionListener);

		machineMinAlignButton.addActionListener(fieldActionListener);

		byValueMinAlignButton.addActionListener(fieldActionListener);

		minAlignValueTextField.addActionListener(fieldActionListener);
		minAlignValueTextField.removeFocusListener(fieldFocusListener);
	}

	/**
	 * Gets called when the user updates the name.
	 */
	protected void updatedName() {
		if (!nameTextField.isShowing()) {
			return;
		}
		// Adjust the value.
		String nameText = this.nameTextField.getText();
		String newName = nameText.trim();
		if (!DataUtilities.isValidDataTypeName(newName)) {
			if (newName.length() == 0) {
				model.setStatus("Name is required.");
			}
			else {
				model.setStatus(newName + " is not a valid name.");
			}
			return;
		}
		String originalDtName = model.getOriginalDataTypeName();
		if (!newName.equals(originalDtName) && newName.length() == 0) {
			nameTextField.setText(originalDtName);
			model.setStatus("Name is required. So original name has been restored.");
			return;
		}

		if (!newName.equals(nameText)) {
			nameTextField.setText(newName);
		}

		if (!newName.equals(model.getCompositeName())) {
			try {
				model.setName(newName);
			}
			catch (DuplicateNameException e) {
				model.setStatus("Can't duplicate name \"" + newName + "\".");
			}
			catch (InvalidNameException e) {
				model.setStatus("\"" + newName + "\" isn't a valid name.");
			}
		}
	}

	/**
	 * Gets called when the user updates the description.
	 */
	protected void updatedDescription() {
		if (!descriptionTextField.isShowing()) {
			return;
		}
		// Adjust the value.
		String newValue = this.descriptionTextField.getText().trim();
		if (!newValue.equals(model.getDescription())) {
			model.setDescription(newValue);
		}
	}

	/**
	 * Returns the currently displayed structure category name.
	 * @return the name
	 */
	public String getCategoryName() {
		return categoryStatusTextField.getText();
	}

	/**
	 * Sets the currently displayed structure category name.
	 * 
	 * @param name
	 *            the new category name
	 */
	public void setCategoryName(String name) {
		categoryStatusTextField.setText(name);
	}

	/**
	 * Returns the currently displayed structure name in the edit area.
	 * @return the name
	 */
	public String getCompositeName() {
		return nameTextField.getText().trim();
	}

	/**
	 * Sets the currently displayed structure name in the edit area.
	 * 
	 * @param name
	 *            the new name
	 */
	public void setCompositeName(String name) {
		String original = getCompositeName();
		if (name.equals(original)) {
			return;
		}
		Document doc = nameTextField.getDocument();
		doc.removeDocumentListener(fieldDocListener);
		nameTextField.setText(name);
		doc.addDocumentListener(fieldDocListener);
	}

	/**
	 * Returns the currently displayed structure description.
	 * @return the description
	 */
	public String getDescription() {
		return descriptionTextField.getText().trim();
	}

	/**
	 * Sets the currently displayed structure description.
	 * 
	 * @param description
	 *            the new description
	 */
	public void setDescription(String description) {
		descriptionTextField.setText(description);
	}

	/**
	 * Checks the GUI to determine if this composite is internally aligned
	 * @return true if interanlly aligned
	 */
	public boolean isInternallyAlignedInGui() {
		return internalAlignmentCheckBox.isSelected();
	}

	/**
	 * Sets the currently displayed structure minimum alignment type
	 * 
	 * @param aligned true if aligned
	 */
	public void setInternallyAligned(boolean aligned) {
		boolean alignedInGui = internalAlignmentCheckBox.isSelected();
		if (alignedInGui != aligned) {
			internalAlignmentCheckBox.setSelected(aligned);
		}
		adjustInternalAlignment();
	}

	/**
	 * Updates the GUI display of the minimum alignment value.
	 */
	public void refreshGUIMinimumAlignmentValue() {
		int minimumAlignment = ((CompEditorModel) model).getMinimumAlignment();
		String value = minAlignValueTextField.getText();
		boolean emptyValue = (value.length() == 0);
		boolean notByValue = ((CompEditorModel) model).viewComposite.isDefaultAligned() ||
			((CompEditorModel) model).viewComposite.isMachineAligned();
		if (notByValue) {
			if (!emptyValue) {
				minAlignValueTextField.setText("");
			}
			return; // No value displayed since default or machine.
		}

		// Change the display to the correct value.
		String minimumAlignmentStr =
			model.showHexNumbers ? CompositeViewerModel.getHexString(minimumAlignment, true)
					: Integer.toString(minimumAlignment);
		minAlignValueTextField.setText(minimumAlignmentStr);
	}

	/**
	 * Updates the GUI display of the actual alignment value.
	 */
	public void refreshGUIActualAlignmentValue() {
		int actualAlignment = ((CompEditorModel) model).viewDTM.getDataOrganization().getAlignment(
			((CompEditorModel) model).viewComposite, ((CompEditorModel) model).getLength());
		String alignmentStr =
			model.showHexNumbers ? CompositeViewerModel.getHexString(actualAlignment, true)
					: Integer.toString(actualAlignment);
		actualAlignmentValueTextField.setText(alignmentStr);
	}

	/**
	 * Returns the currently displayed composite's size.
	 * @return the size
	 */
	public int getCompositeSize() {
		return Integer.decode(sizeStatusTextField.getText());
	}

	/**
	 * Sets the currently displayed composite's size.
	 * 
	 * @param size the new size
	 */
	public void setCompositeSize(int size) {
		boolean sizeIsEditable = ((CompEditorModel) model).isSizeEditable();
		if (sizeStatusTextField.isEditable() != sizeIsEditable) {
			sizeStatusTextField.setEditable(sizeIsEditable);
		}
		String sizeStr = model.showHexNumbers ? CompositeViewerModel.getHexString(size, true)
				: Integer.toString(size);
		sizeStatusTextField.setText(sizeStr);
	}

	@Override
	public void dragUnderFeedback(boolean ok, DropTargetDragEvent e) {
		synchronized (table) {
			int dropAction = e.getDropAction();
			boolean actionChanged = false;
			if (dropAction != lastDndAction) {
				actionChanged = true;
				lastDndAction = dropAction;
			}
			if (table.isEditing()) {
				table.editingCanceled(null);
			}
			boolean inserting = false;
			if (dropAction == DnDConstants.ACTION_COPY) {
				inserting = true;
			}
			dndTableCellRenderer.selectRange(inserting);
			dndDtiCellRenderer.selectRange(inserting);
			Point p = e.getLocation();
			int row = table.rowAtPoint(p);
			boolean setRow = dndTableCellRenderer.setRowForFeedback(row);
			boolean setDtiRow = dndDtiCellRenderer.setRowForFeedback(row);
			if (actionChanged || setRow || setDtiRow) {
				table.repaint();
			}
		}
	}

	/**
	 * Called from the DropTgtAdapter to revert any feedback changes back to
	 * normal.
	 */
	@Override
	public void undoDragUnderFeedback() {
		synchronized (table) {
			dndTableCellRenderer.setRowForFeedback(-1);
			dndDtiCellRenderer.setRowForFeedback(-1);
			table.repaint();
		}
	}

	@Override
	public void showUndefinedStateChanged(boolean showUndefinedBytes) {
		// TODO Auto-generated method stub

	}

}
