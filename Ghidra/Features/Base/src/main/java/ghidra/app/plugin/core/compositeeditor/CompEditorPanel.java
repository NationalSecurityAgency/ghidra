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
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.Document;

import docking.widgets.OptionDialog;
import docking.widgets.button.GRadioButton;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitAttributes;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.HelpLocation;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for editing a composite with a blank line at the bottom of the table
 * when in unlocked mode.
 */
public class CompEditorPanel extends CompositeEditorPanel {

	protected final static Insets LEFT_INSETS = new Insets(2, 3, 1, 0);
	protected final static Insets VERTICAL_INSETS = new Insets(2, 0, 1, 0);

	// GUI components for displaying composite data type information.
	private GridBagLayout gridBagLayout;
	private JPanel infoPanel;
	private JLabel nameLabel;
	protected JTextField nameTextField;
	private JLabel descriptionLabel;
	private JTextField descriptionTextField;
	private JLabel categoryLabel;
	private JTextField categoryStatusTextField;
	private JLabel sizeLabel;
	private JTextField sizeTextField;

	private JPanel alignPanel;
	private JRadioButton defaultAlignButton;
	private JRadioButton machineAlignButton;
	private JRadioButton explicitAlignButton;
	private JTextField explicitAlignTextField;

	private JPanel packingPanel;
	private JCheckBox packingEnablementButton;
	private JRadioButton defaultPackingButton;
	private JRadioButton explicitPackingButton;
	private JTextField explicitPackingTextField;

	private JLabel actualAlignmentLabel;
	private JTextField actualAlignmentValueTextField;

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
	}

	@Override
	public void dispose() {
		removeFieldListeners();
		super.dispose();
	}

	@Override
	public void componentDataChanged() {
		refreshGUIPackingValue();
		refreshGUIMinimumAlignmentValue();
		refreshGUIActualAlignmentValue();
		setCompositeSize(model.getLength());
	}

	@Override
	public void compositeInfoChanged() {
		adjustCompositeInfo();
		if (bitViewComponent != null &&
			model.showHexNumbers != bitViewComponent.isShowOffsetsInHex()) {
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
		componentDataChanged();
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

				if (dtc != null && dtc.getOffset() >= length) {
					// likely trailing zero-length component - not in range for bitViewComponent
					bitViewComponent.init(null);
				}
				else {
					bitViewComponent.init(dtc);
				}

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

	@Override
	public Dimension getPreferredSize() {
		// make sure our preferred size accounts for that of our components that the user 
		// may choose to show 
		Dimension preferredSize = super.getPreferredSize();
		if (alignPanel.isShowing()) {
			return preferredSize;
		}

		Dimension alignmentPanelPreferredSize = alignPanel.getPreferredSize();
		preferredSize.width += alignmentPanelPreferredSize.width;

		Dimension packingPanelPreferredSize = packingPanel.getPreferredSize();
		preferredSize.width += packingPanelPreferredSize.width;

		return preferredSize;
	}

	private void setupMinimumAlignment() {

		DataOrganization dataOrganization =
			((CompEditorModel) model).viewComposite.getDataOrganization();
		int machineAlignment = dataOrganization.getMachineAlignment();

		defaultAlignButton = new GRadioButton("default           ");
		explicitAlignButton = new GRadioButton();
		explicitAlignTextField = new JTextField();
		machineAlignButton = new GRadioButton("machine: " + machineAlignment);
		setupDefaultMinAlignButton();
		setupExplicitAlignButton();
		setupMachineMinAlignButton();
		ButtonGroup minAlignGroup = new ButtonGroup();
		minAlignGroup.add(defaultAlignButton);
		minAlignGroup.add(explicitAlignButton);
		minAlignGroup.add(machineAlignButton);

		alignPanel = new JPanel(new GridBagLayout());
		TitledBorder border = BorderFactory.createTitledBorder("align (minimum)");
//		border.setTitlePosition(TitledBorder.ABOVE_TOP);
		alignPanel.setBorder(border);
		if (helpManager != null) {
			helpManager.registerHelp(alignPanel,
				new HelpLocation(provider.getHelpTopic(), provider.getHelpName() + "_" + "Align"));
		}
		String alignmentToolTip =
			"<HTML>The <B>align</B> control allows the overall minimum alignment of this<BR>" +
				"data type to be specified.  The actual computed alignment<BR>" +
				"may be any multiple of this value.   <font color=blue size=\"-2\">(&lt;F1&gt; for help)</HTML>";
		alignPanel.setToolTipText(alignmentToolTip);

		addMinimumAlignmentComponents();

		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 5;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridheight = 4;
		infoPanel.add(alignPanel, gridBagConstraints);
		infoPanel.invalidate();

		refreshGUIActualAlignmentValue();
	}

	private void addMinimumAlignmentComponents() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 2;
		alignPanel.add(defaultAlignButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		alignPanel.add(explicitAlignButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		alignPanel.add(explicitAlignTextField, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 2;
		alignPanel.add(machineAlignButton, gridBagConstraints);
	}

	private void setupDefaultMinAlignButton() {
		defaultAlignButton.setName("Default Alignment");
		String alignmentToolTip =
			"<HTML>Sets this data type to use <B>default</B> alignment.<BR>" +
				"If packing is disabled, the default will be 1 byte.  If packing<BR>" +
				"is enabled, the alignment is computed based upon the pack<BR>" +
				"setting and the alignment of each component data type.</HTML>";

		defaultAlignButton.addActionListener(e -> {
			((CompEditorModel) model).setAlignmentType(AlignmentType.DEFAULT, -1);
		});

		defaultAlignButton.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(defaultAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "Align"));
		}
	}

	private void setupMachineMinAlignButton() {
		machineAlignButton.setName("Machine Alignment");
		String alignmentToolTip =
			"<HTML>Sets this data type to use the <B>machine</B> alignment<BR>" +
				"as specified by the compiler specification.  If packing is<BR>" +
				"enabled, the computed alignment of this composite should be<BR>" +
				"the machine alignment value.</HTML>";
		machineAlignButton.setToolTipText(alignmentToolTip);

		machineAlignButton.addActionListener(e -> {
			((CompEditorModel) model).setAlignmentType(AlignmentType.MACHINE, -1);
		});

		if (helpManager != null) {
			helpManager.registerHelp(machineAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "Align"));
		}
	}

	private void setupExplicitAlignButton() {
		explicitAlignButton.setName("Explicit Alignment");
		String alignmentToolTip =
			"<HTML>Sets this data type to use the <B>explicit</B> alignment value<BR>" +
				"specified.  If packing is enabled, the computed alignment of<BR>" +
				"this composite may be any multiple of this value.</HTML>";
		explicitAlignButton.setToolTipText(alignmentToolTip);

		explicitAlignButton.addActionListener(e -> {
			chooseExplicitAlign();
		});

		if (helpManager != null) {
			helpManager.registerHelp(explicitAlignButton, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "Align"));
		}

		explicitAlignTextField.setName("Explicit Alignment Value");
		explicitAlignTextField.setEditable(true);
		explicitAlignTextField.addActionListener(e -> adjustExplicitMinimumAlignmentValue());

		explicitAlignTextField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				if (explicitAlignButton.isSelected()) {
					return;
				}
				explicitAlignButton.setSelected(true);
				chooseExplicitAlign();
			}

			@Override
			public void focusLost(FocusEvent e) {
				adjustExplicitMinimumAlignmentValue();
			}
		});

		explicitAlignTextField.setToolTipText(alignmentToolTip);
		if (helpManager != null) {
			helpManager.registerHelp(explicitAlignTextField, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "Align"));
		}

		refreshGUIMinimumAlignmentValue(); // Display the initial value.
	}

	private void adjustExplicitMinimumAlignmentValue() {
		setStatus(null);
		String value = explicitAlignTextField.getText();
		try {
			int minAlignment = Integer.decode(value.trim());
			try {
				((CompEditorModel) model).setAlignmentType(AlignmentType.EXPLICIT, minAlignment);
				adjustCompositeInfo();
			}
			catch (IllegalArgumentException e1) {
				refreshGUIMinimumAlignmentValue();
				String message = "\"" + value + "\" is not a valid alignment value.";
				setStatus(message);
			}
		}
		catch (NumberFormatException e1) {
			refreshGUIMinimumAlignmentValue();
			String message = "\"" + value + "\" is not a valid alignment value.";
			setStatus(message);
		}
	}

	private void setupActualAlignment() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		String actualAlignmentToolTip =
			"<HTML>The actual alignment to be used for this data type.<BR>" +
				"A combination of the pack and alignment settings made to this datatype<BR>" +
				"combined with alignments of the individual components are used to<BR>" +
				"to compute the actual alignment of this datatype.</HTML>";

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
		actualAlignmentValueTextField.setText("" + ((CompEditorModel) model).getActualAlignment());
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
		actualAlignmentValueTextField.setBackground(new Color(getBackground().getRGB()));
	}

	private void setupPacking() {

		packingPanel = new JPanel(new VerticalLayout(0));

		packingEnablementButton = new JCheckBox("pack");
		packingEnablementButton.setEnabled(true);
		packingEnablementButton.setFont(UIManager.getFont("TitledBorder.font"));
		packingEnablementButton.setForeground(UIManager.getColor("TitledBorder.titleColor"));
		packingPanel.add(packingEnablementButton);

		JPanel innerPanel = new JPanel(new GridBagLayout());
		innerPanel.setBorder(UIManager.getBorder("TitledBorder.border"));
		packingPanel.add(innerPanel);

		defaultPackingButton = new GRadioButton("default           ");
		explicitPackingButton = new GRadioButton();
		explicitPackingTextField = new JTextField();

		setupDefaultPackingButton();
		setupExplicitPackingButton();
		setupPackingEnablementButton();

		ButtonGroup packingGroup = new ButtonGroup();
		packingGroup.add(defaultPackingButton);
		packingGroup.add(explicitPackingButton);

		if (helpManager != null) {
			helpManager.registerHelp(packingPanel, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "Pack"));
		}

		addPackingComponents(innerPanel);

		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 7;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridheight = 4;
		infoPanel.add(packingPanel, gridBagConstraints);

		refreshGUIPackingValue();
	}

	private void addPackingComponents(JPanel gridPanel) {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 2;
		gridPanel.add(defaultPackingButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		gridPanel.add(explicitPackingButton, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 1;
		gridPanel.add(explicitPackingTextField, gridBagConstraints);

		gridBagConstraints.anchor = GridBagConstraints.WEST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 2;
//		gridPanel.add(disabledPackingButton, gridBagConstraints);
	}

	private void setupPackingEnablementButton() {
		packingEnablementButton.setName("Packing Enablement");
		String packingToolTipText =
			"<HTML>Enable packing when details of all components are known (including sizing and alignment).<BR>" +
				"Disable packing when Reverse Engineering composite.   <font color=blue size=\"-2\">(&lt;F1&gt; for help)</font></HTML>";
		packingEnablementButton.addActionListener(e -> {
			((CompEditorModel) model).setPackingType(
				packingEnablementButton.isSelected() ? PackingType.DEFAULT : PackingType.DISABLED,
				-1);
		});

		packingEnablementButton.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(packingEnablementButton,
				new HelpLocation(provider.getHelpTopic(), provider.getHelpName() + "_" + "Pack"));
		}
	}

	private void setupDefaultPackingButton() {
		defaultPackingButton.setName("Default Packing");
		String packingToolTipText =
			"<HTML>Indicates <B>default</B> compiler packing rules should be applied.</HTML>";

		defaultPackingButton.addActionListener(e -> {
			((CompEditorModel) model).setPackingType(PackingType.DEFAULT, -1);
		});

		defaultPackingButton.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(defaultPackingButton, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "Pack"));
		}
	}

	private void setupExplicitPackingButton() {
		explicitPackingButton.setName("Explicit Packing");
		String packingToolTipText =
			"<HTML>Indicates an explicit pack size should be applied.</HTML>";

		explicitPackingButton.addActionListener(e -> chooseByValuePacking());
		explicitPackingButton.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(explicitPackingButton, new HelpLocation(provider.getHelpTopic(),
				provider.getHelpName() + "_" + "Pack"));
		}

		explicitPackingTextField.setName("Packing Value");
		explicitPackingTextField.setEditable(true);
		explicitPackingTextField.addActionListener(e -> adjustPackingValue());

		explicitPackingTextField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				if (explicitPackingButton.isSelected()) {
					return;
				}
				explicitPackingButton.setSelected(true);
				chooseByValuePacking();
			}

			@Override
			public void focusLost(FocusEvent e) {
				adjustPackingValue();
			}
		});

		explicitPackingTextField.setToolTipText(packingToolTipText);
		if (helpManager != null) {
			helpManager.registerHelp(explicitPackingTextField, new HelpLocation(
				provider.getHelpTopic(), provider.getHelpName() + "_" + "Pack"));
		}
	}

	private void chooseByValuePacking() {
		((CompEditorModel) model).setPackingType(PackingType.EXPLICIT, 1);
		explicitPackingTextField.selectAll();
		explicitPackingTextField.requestFocus();
	}

	private void adjustPackingValue() {
		setStatus(null);
		String value = explicitPackingTextField.getText();
		try {
			int explicitPacking = Integer.decode(value.trim());
			((CompEditorModel) model).setPackingType(PackingType.EXPLICIT, explicitPacking);
			adjustCompositeInfo();
		}
		catch (NumberFormatException e1) {
			refreshGUIPackingValue();
			setStatus(value + " is not a valid packing value.");
		}
	}

	/**
	 * Sets the currently displayed structure packing value (maximum component alignment)
	 */
	public void refreshGUIPackingValue() {
		PackingType packingType = ((CompEditorModel) model).getPackingType();
		String packingString = "";

		boolean packingEnabled = packingType != PackingType.DISABLED;
		packingEnablementButton.setSelected(packingEnabled);

		defaultPackingButton.setEnabled(packingEnabled);
		explicitPackingButton.setEnabled(packingEnabled);
		explicitPackingTextField.setEnabled(packingEnabled);

		if (packingType == PackingType.DEFAULT) {
			defaultPackingButton.setSelected(true);
		}
		else if (packingType == PackingType.EXPLICIT) {
			int packValue = ((CompEditorModel) model).getExplicitPackingValue();
			packingString =
				model.showHexNumbers ? CompositeViewerModel.getHexString(packValue, true)
						: Integer.toString(packValue);
			explicitPackingButton.setSelected(true);
		}
		explicitPackingTextField.setText(packingString);
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

		sizeTextField = new JTextField(10);
		sizeTextField.setName("Total Length");
		sizeTextField.setToolTipText("The current size in bytes.");
		setSizeEditable(false);
		gridBagConstraints.ipadx = 60;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 3;
		infoPanel.add(sizeTextField, gridBagConstraints);

		sizeTextField.addActionListener(e -> updatedStructureSize());
		sizeTextField.addFocusListener(new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// don't care
			}

			@Override
			public void focusLost(FocusEvent e) {
				if (sizeTextField.isEditable()) {
					updatedStructureSize();
				}
			}
		});
	}

	protected void setSizeEditable(boolean editable) {
		sizeTextField.setEditable(editable);
		if (editable) {
			// editable - use same background as category field
			sizeTextField.setBackground(descriptionTextField.getBackground());
		}
		else {
			// not editable - use same background as panel
			sizeTextField.setBackground(new Color(getBackground().getRGB()));
		}
	}

	private void updatedStructureSize() {

		if (updatingSize) {
			return;
		}
		if (!sizeTextField.isShowing()) {
			return;
		}

		if (!((CompEditorModel) model).isSizeEditable()) {
			return;
		}

		String valueStr = sizeTextField.getText();
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
				model.setStatus(null);
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
		};
		nameTextField.addActionListener(fieldActionListener);
		descriptionTextField.addActionListener(fieldActionListener);

		fieldFocusListener = new FocusListener() {
			@Override
			public void focusGained(FocusEvent e) {
				// ignore
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
			}
		};
		nameTextField.addFocusListener(fieldFocusListener);
		descriptionTextField.addFocusListener(fieldFocusListener);
	}

	private void chooseExplicitAlign() {
		if (((CompEditorModel) model).getAlignmentType() != AlignmentType.EXPLICIT) {
			Composite viewComposite = ((CompEditorModel) model).viewComposite;
			int defaultValue = 1;
			if (viewComposite.isPackingEnabled()) {
				defaultValue = viewComposite.getDataOrganization().getMachineAlignment();
			}
			((CompEditorModel) model).setAlignmentType(AlignmentType.EXPLICIT,
				defaultValue);
		}
		explicitAlignTextField.selectAll();
		explicitAlignTextField.requestFocus();
	}

	private void removeFieldListeners() {
		nameTextField.getDocument().removeDocumentListener(fieldDocListener);
		nameTextField.removeActionListener(fieldActionListener);
		nameTextField.removeFocusListener(fieldFocusListener);

		descriptionTextField.getDocument().removeDocumentListener(fieldDocListener);
		descriptionTextField.removeActionListener(fieldActionListener);
		descriptionTextField.removeFocusListener(fieldFocusListener);

		defaultAlignButton.addActionListener(fieldActionListener);

		machineAlignButton.addActionListener(fieldActionListener);

		explicitAlignButton.addActionListener(fieldActionListener);

		explicitAlignTextField.addActionListener(fieldActionListener);
		explicitAlignTextField.removeFocusListener(fieldFocusListener);
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

	public void refreshGUIMinimumAlignmentValue() {

		AlignmentType alignmentType = ((CompEditorModel) model).getAlignmentType();
		String minimumAlignmentStr = "";
		if (alignmentType == AlignmentType.DEFAULT) {
			defaultAlignButton.setSelected(true);
		}
		else if (alignmentType == AlignmentType.MACHINE) {
			machineAlignButton.setSelected(true);
		}
		else {
			explicitAlignButton.setSelected(true);
			int minimumAlignment = ((CompEditorModel) model).getExplicitMinimumAlignment();
			minimumAlignmentStr =
				model.showHexNumbers ? CompositeViewerModel.getHexString(minimumAlignment, true)
						: Integer.toString(minimumAlignment);
		}
		explicitAlignTextField.setText(minimumAlignmentStr);
	}

	/**
	 * Updates the GUI display of the actual alignment value.
	 */
	public void refreshGUIActualAlignmentValue() {
		int actualAlignment = ((CompEditorModel) model).getActualAlignment();
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
		return Integer.decode(sizeTextField.getText());
	}

	/**
	 * Sets the currently displayed composite's size.
	 * 
	 * @param size the new size
	 */
	public void setCompositeSize(int size) {
		boolean sizeIsEditable = ((CompEditorModel) model).isSizeEditable();
		if (sizeTextField.isEditable() != sizeIsEditable) {
			setSizeEditable(sizeIsEditable);
		}
		String sizeStr = model.showHexNumbers ? CompositeViewerModel.getHexString(size, true)
				: Integer.toString(size);
		sizeTextField.setText(sizeStr);
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
