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

import static docking.widgets.textfield.GFormattedTextField.Status.*;

import java.awt.*;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTargetDragEvent;
import java.awt.event.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.text.DefaultFormatterFactory;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.OptionDialog;
import docking.widgets.button.GRadioButton;
import docking.widgets.fieldpanel.support.FieldSelection;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.GFormattedTextField;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.theme.GThemeDefaults.Colors.Viewport;
import generic.theme.Gui;
import ghidra.app.plugin.core.compositeeditor.BitFieldPlacementComponent.BitAttributes;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Composite;
import ghidra.util.InvalidNameException;
import ghidra.util.Swing;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

/**
 * Panel for editing a composite with a blank line at the bottom of the table
 * when in unlocked mode.
 */
public class CompEditorPanel extends CompositeEditorPanel {

	protected final static Insets LEFT_INSETS = new Insets(2, 3, 1, 0);
	protected final static Insets VERTICAL_INSETS = new Insets(2, 2, 1, 0);

	// GUI components for displaying composite data type information.
	private GridBagLayout gridBagLayout;
	private JPanel infoPanel;
	private JLabel categoryNameLabel;
	GFormattedTextField nameTextField; // exposed to package for testing only
	private GFormattedTextField descriptionTextField;
	private GFormattedTextField sizeTextField;

	private JPanel alignPanel;
	private JRadioButton defaultAlignButton;
	private JRadioButton machineAlignButton;
	private JRadioButton explicitAlignButton;
	private GFormattedTextField explicitAlignTextField;

	private JPanel packingPanel;
	private JCheckBox packingEnablementButton;
	private JRadioButton defaultPackingButton;
	private JRadioButton explicitPackingButton;
	private GFormattedTextField explicitPackingTextField;

	private JLabel actualAlignmentValueLabel;

	private List<Component> focusList;

	private BitFieldPlacementComponent bitViewComponent;

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

		bitViewScrollPane.getViewport().setBackground(Viewport.UNEDITABLE_BACKGROUND);
		bitViewScrollPane.setBorder(null);

		// establish default preferred size of panel based upon fixed preferred height of bitViewComponent
		Dimension bitViewerDefaultSize = new Dimension(800, bitViewComponent.getPreferredHeight());
		bitViewScrollPane.setPreferredSize(bitViewerDefaultSize);

		bitViewPanel.add(bitViewScrollPane);
		return bitViewPanel;
	}

	@Override
	protected List<Component> getFocusComponents() {
		if (focusList == null) {
			//@formatter:off
			focusList = List.of(
				
				table,
				searchPanel.getTextField(),
				nameTextField,
				descriptionTextField,
				sizeTextField,
				
				// add the first radio button; the rest are reachable via arrow keys
				defaultAlignButton, 
				packingEnablementButton,
				
				// add the first radio button; the rest are reachable via arrow keys
				defaultPackingButton
			);
			//@formatter:on
		}
		return focusList;
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

		setupCategory();
		setupName();
		setupDescription();
		setupSize();
		setupActualAlignment();
		setupMinimumAlignment();
		setupPacking();

		infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 0, 5));

		return infoPanel;
	}

	private void setupCategory() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		JLabel categoryLabel = new GDLabel("Category:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 0;
		infoPanel.add(categoryLabel, gridBagConstraints);

		categoryNameLabel = new JLabel(" ");
		categoryNameLabel.setToolTipText("Category of this composite data type.");
		gridBagConstraints.insets = new Insets(2, 4, 1, 2);
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 0;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(categoryNameLabel, gridBagConstraints);
	}

	private void setupName() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		JLabel nameLabel = new GDLabel("Name:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 1;
		infoPanel.add(nameLabel, gridBagConstraints);

		nameTextField = new GFormattedTextField(new DefaultFormatterFactory(), "");
		nameTextField.setToolTipText("Structure Name");
		nameTextField.setEditable(true);

		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 1;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(nameTextField, gridBagConstraints);

		provider.registerHelp(nameTextField, "Name");

		nameTextField.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				model.clearStatus();
				String newName = nameTextField.getText().trim();
				if (!DataUtilities.isValidDataTypeName(newName)) {
					if (newName.length() == 0) {
						model.setStatus("Name is required.");
					}
					else {
						model.setStatus(newName + " is not a valid name.");
					}
					return false;
				}
				if (!newName.equals(model.getOriginalDataTypeName()) &&
					model.getOriginalDataTypeManager()
							.getDataType(model.originalDataTypePath.getCategoryPath(),
								newName) != null) {
					model.setStatus("A data type named " + newName + " already exists.");
					return false;
				}
				updateEntryAcceptanceStatus();
				return true;
			}
		});

		nameTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					e.consume();
					// revert to model state when escape is hit
					setCompositeName(model.getCompositeName());
				}
			}
		});

		nameTextField.addTextEntryStatusListener(c -> provider.contextChanged());

		nameTextField.addActionListener(e -> updatedName());

		nameTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				updatedName();
			}
		});
	}

	private void setupDescription() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		JLabel descriptionLabel = new GDLabel("Description:");
		gridBagConstraints.insets = LEFT_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.weightx = 0;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 2;
		infoPanel.add(descriptionLabel, gridBagConstraints);

		descriptionTextField = new GFormattedTextField(new DefaultFormatterFactory(), "");
		descriptionTextField.setToolTipText("Structure Description");
		descriptionTextField.setEditable(true);

		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.weightx = 1;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 2;
		gridBagConstraints.gridwidth = 4;
		infoPanel.add(descriptionTextField, gridBagConstraints);

		provider.registerHelp(descriptionTextField, "Description");

		descriptionTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					e.consume();
					// revert to model state when escape is hit
					setDescription(model.getDescription());
				}
			}
		});

		descriptionTextField.addTextEntryStatusListener(c -> provider.contextChanged());

		descriptionTextField.addActionListener(e -> updatedDescription());

		descriptionTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusLost(FocusEvent e) {
				updatedDescription();
			}
		});
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

		setupDefaultAlignButton();
		setupExplicitAlignButtonAndTextField();
		setupMachineMinAlignButton();

		ButtonGroup minAlignGroup = new ButtonGroup();
		minAlignGroup.add(defaultAlignButton);
		minAlignGroup.add(explicitAlignButton);
		minAlignGroup.add(machineAlignButton);

		alignPanel = new JPanel(new GridBagLayout());
		TitledBorder border = BorderFactory.createTitledBorder("align (minimum)");

		alignPanel.setBorder(border);
		provider.registerHelp(alignPanel, "Align");

		String alignmentToolTip =
			"<html>The <B>align</B> control allows the overall minimum alignment of this<BR>" +
				"data type to be specified.  The actual computed alignment<BR>" +
				"may be any multiple of this value.   " + "<font color=\"" +
				Palette.BLUE.toHexString() + "\" size=\"-2\">(&lt;F1&gt; for help)</html>";
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

		refreshGUIMinimumAlignmentValue(); // Display the initial value.
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

	private void setupDefaultAlignButton() {
		defaultAlignButton = new GRadioButton("default           ");

		defaultAlignButton.setName("Default Alignment");
		String alignmentToolTip = "<html>Sets this data type to use <B>default</B> alignment.<BR>" +
			"If packing is disabled, the default will be 1 byte.  If packing<BR>" +
			"is enabled, the alignment is computed based upon the pack<BR>" +
			"setting and the alignment of each component data type.</html>";

		defaultAlignButton.addActionListener(e -> {
			((CompEditorModel) model).setAlignmentType(AlignmentType.DEFAULT, -1);
		});

		defaultAlignButton.setToolTipText(alignmentToolTip);
		provider.registerHelp(defaultAlignButton, "Align");
	}

	private void setupMachineMinAlignButton() {
		DataOrganization dataOrganization =
			((CompEditorModel) model).viewComposite.getDataOrganization();
		int machineAlignment = dataOrganization.getMachineAlignment();

		machineAlignButton = new GRadioButton("machine: " + machineAlignment);

		machineAlignButton.setName("Machine Alignment");
		String alignmentToolTip =
			"<html>Sets this data type to use the <B>machine</B> alignment<BR>" +
				"as specified by the compiler specification.  If packing is<BR>" +
				"enabled, the computed alignment of this composite should be<BR>" +
				"the machine alignment value.</html>";
		machineAlignButton.setToolTipText(alignmentToolTip);

		machineAlignButton.addActionListener(e -> {
			((CompEditorModel) model).setAlignmentType(AlignmentType.MACHINE, -1);
		});

		provider.registerHelp(machineAlignButton, "Align");
	}

	private void setupExplicitAlignButtonAndTextField() {
		explicitAlignButton = new GRadioButton();
		explicitAlignButton.setName("Explicit Alignment");

		explicitAlignTextField = new GFormattedTextField(new DefaultFormatterFactory(), "");
		explicitAlignTextField.setName("Explicit Alignment Value");
		explicitAlignTextField.setEditable(true);

		String alignmentToolTip =
			"<html>Sets this data type to use the <B>explicit</B> alignment value<BR>" +
				"specified.  If packing is enabled, the computed alignment of<BR>" +
				"this composite may be any multiple of this value.</html>";
		explicitAlignButton.setToolTipText(alignmentToolTip);
		explicitAlignTextField.setToolTipText(alignmentToolTip);

		provider.registerHelp(explicitAlignButton, "Align");
		provider.registerHelp(explicitAlignTextField, "Align");

		// As a convenience, when this radio button is focused, change focus to the editor field
		explicitAlignButton.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				explicitAlignTextField.requestFocus();
			}
		});

		explicitAlignButton.addActionListener(e -> chooseExplicitAlign());

		explicitAlignTextField.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				return decodeUnsignedIntEntry(explicitAlignTextField, "minimum alignment",
					false) > 0;
			}
		});

		explicitAlignTextField
				.addKeyListener(new UpAndDownKeyListener(defaultAlignButton, machineAlignButton));

		explicitAlignTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					e.consume();
					// revert to model state when escape is hit
					refreshGUIMinimumAlignmentValue();
				}
			}
		});

		explicitAlignTextField.addTextEntryStatusListener(c -> provider.contextChanged());

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

	}

	private void adjustExplicitMinimumAlignmentValue() {
		if (explicitAlignTextField.getTextEntryStatus() != CHANGED) {
			return;
		}
		int minAlignment =
			decodeUnsignedIntEntry(explicitAlignTextField, "minimum alignment", false);
		if (minAlignment <= 0) {
			return;
		}
		try {
			((CompEditorModel) model).setAlignmentType(AlignmentType.EXPLICIT, minAlignment);
			adjustCompositeInfo();
		}
		catch (IllegalArgumentException e1) {
			refreshGUIMinimumAlignmentValue();
			String message = "\"" + minAlignment + "\" is not a valid alignment value.";
			setStatus(message);
		}
	}

	private void setupActualAlignment() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();
		String actualAlignmentToolTip =
			"<html>The actual alignment to be used for this data type.<BR>" +
				"A combination of the pack and alignment settings made to this datatype<BR>" +
				"combined with alignments of the individual components are used to<BR>" +
				"to compute the actual alignment of this datatype.</html>";

		JPanel actualAlignmentPanel = new JPanel(new BorderLayout());
		JLabel actualAlignmentLabel = new GDLabel("Alignment:");
		gridBagConstraints.insets = new Insets(2, 10, 2, 2);
		gridBagConstraints.anchor = GridBagConstraints.EAST;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 2;
		gridBagConstraints.gridy = 3;
		actualAlignmentLabel.setToolTipText(actualAlignmentToolTip);
		actualAlignmentPanel.add(actualAlignmentLabel, BorderLayout.EAST);
		infoPanel.add(actualAlignmentPanel, gridBagConstraints);

		actualAlignmentValueLabel = new JLabel();
		int actualAlignment = ((CompEditorModel) model).getActualAlignment();
		actualAlignmentValueLabel.setText(Integer.toString(actualAlignment));
		actualAlignmentValueLabel.setToolTipText(actualAlignmentToolTip);
		actualAlignmentValueLabel.setBackground(getBackground());
		actualAlignmentValueLabel.setName("Actual Alignment Value");

		provider.registerHelp(actualAlignmentValueLabel, "ActualAlignment");

		gridBagConstraints.insets = new Insets(2, 4, 1, 2);
		gridBagConstraints.anchor = GridBagConstraints.LINE_START;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.ipadx = 50;
		gridBagConstraints.gridx = 3;
		gridBagConstraints.gridy = 3;
		infoPanel.add(actualAlignmentValueLabel, gridBagConstraints);

		refreshGUIActualAlignmentValue();
	}

	private void setupPacking() {

		packingPanel = new JPanel(new VerticalLayout(0));

		packingEnablementButton = new JCheckBox("pack");
		packingEnablementButton.setEnabled(true);
		packingEnablementButton.setFont(UIManager.getFont("TitledBorder.font"));
		packingEnablementButton.setForeground(UIManager.getColor("TitledBorder.titleColor"));
		packingPanel.add(packingEnablementButton);

		JPanel innerPanel = new JPanel(new GridBagLayout());
		Border titledBorder = UIManager.getBorder("TitledBorder.border");
		innerPanel.setBorder(titledBorder);
		packingPanel.add(innerPanel);

		// Since we set the border manually, it does not get updated when switching LaFs.  Add a 
		// theme listener to update the border ourselves.
		Gui.addThemeListener(e -> {
			if (e.isLookAndFeelChanged()) {
				Border updatedTitledBorder = UIManager.getBorder("TitledBorder.border");
				innerPanel.setBorder(updatedTitledBorder);
			}
		});

		setupDefaultPackingButton();
		setupExplicitPackingButtonAndTextField();
		setupPackingEnablementButton();

		ButtonGroup packingGroup = new ButtonGroup();
		packingGroup.add(defaultPackingButton);
		packingGroup.add(explicitPackingButton);

		provider.registerHelp(packingPanel, "Pack");

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

	}

	private void setupPackingEnablementButton() {
		packingEnablementButton.setName("Packing Enablement");
		String packingToolTipText =
			"<html>Enable packing when details of all components are known (including sizing and" +
				" alignment).<BR>" + "Disable packing when Reverse Engineering composite.   " +
				"<font color=\"" + Palette.BLUE.toHexString() +
				"\" size=\"-2\">(&lt;F1&gt; for help)</font></html>";
		packingEnablementButton.addActionListener(e -> {
			((CompEditorModel) model).setPackingType(
				packingEnablementButton.isSelected() ? PackingType.DEFAULT : PackingType.DISABLED,
				-1);
		});

		packingEnablementButton.setToolTipText(packingToolTipText);

		provider.registerHelp(packingEnablementButton, "Pack");
	}

	private void setupDefaultPackingButton() {
		defaultPackingButton = new GRadioButton("default           ");

		defaultPackingButton.setName("Default Packing");
		String packingToolTipText =
			"<html>Indicates <B>default</B> compiler packing rules should be applied.</html>";

		defaultPackingButton.addActionListener(e -> {
			((CompEditorModel) model).setPackingType(PackingType.DEFAULT, -1);
		});

		defaultPackingButton.setToolTipText(packingToolTipText);
		provider.registerHelp(defaultPackingButton, "Pack");
	}

	private void setupExplicitPackingButtonAndTextField() {
		explicitPackingButton = new GRadioButton();
		explicitPackingButton.setName("Explicit Packing");

		explicitPackingTextField = new GFormattedTextField(new DefaultFormatterFactory(), "");
		explicitPackingTextField.setName("Packing Value");
		explicitPackingTextField.setEditable(true);

		String packingToolTipText =
			"<html>Indicates an explicit pack size should be applied.</html>";
		explicitPackingButton.setToolTipText(packingToolTipText);
		explicitPackingTextField.setToolTipText(packingToolTipText);

		provider.registerHelp(explicitPackingButton, "Pack");
		provider.registerHelp(explicitPackingTextField, "Pack");

		// As a convenience, when this radio button is focused, change focus to the editor field
		explicitPackingButton.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				explicitPackingTextField.requestFocus();
			}
		});

		explicitPackingButton.addActionListener(e -> chooseByValuePacking());

		explicitPackingTextField.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				return decodeUnsignedIntEntry(explicitPackingTextField, "pack value", false) > 0;
			}
		});

		explicitPackingTextField.addKeyListener(
			new UpAndDownKeyListener(defaultPackingButton, defaultPackingButton));

		explicitPackingTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					e.consume();
					// revert to model state when escape is hit
					refreshGUIPackingValue();
				}
			}
		});

		explicitPackingTextField.addTextEntryStatusListener(c -> provider.contextChanged());

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

	}

	private void chooseByValuePacking() {
		((CompEditorModel) model).setPackingType(PackingType.EXPLICIT, 1);
		explicitPackingTextField.selectAll();
		explicitPackingTextField.requestFocus();
	}

	private void adjustPackingValue() {
		if (explicitPackingTextField.getTextEntryStatus() != CHANGED) {
			return;
		}
		int explicitPacking = decodeUnsignedIntEntry(explicitPackingTextField, "pack value", false);
		if (explicitPacking <= 0) {
			return;
		}
		((CompEditorModel) model).setPackingType(PackingType.EXPLICIT, explicitPacking);
		adjustCompositeInfo();
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
		explicitPackingTextField.setDefaultValue(packingString);
		explicitPackingTextField.setIsError(false);
	}

	protected void setupSize() {
		GridBagConstraints gridBagConstraints = new GridBagConstraints();

		JLabel sizeLabel = new GDLabel("Size:");
		sizeLabel.setToolTipText("The current size in bytes.");
		gridBagConstraints.anchor = GridBagConstraints.LINE_END;
		gridBagConstraints.fill = GridBagConstraints.NONE;
		gridBagConstraints.gridx = 0;
		gridBagConstraints.gridy = 3;
		infoPanel.add(sizeLabel, gridBagConstraints);

		sizeTextField = new GFormattedTextField(new DefaultFormatterFactory(), "");
		sizeTextField.setName("Total Length");
		sizeTextField.setToolTipText("The current size in bytes.");
		setSizeEditable(false);

		gridBagConstraints.ipadx = 60;
		gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
		gridBagConstraints.insets = VERTICAL_INSETS;
		gridBagConstraints.gridx = 1;
		gridBagConstraints.gridy = 3;
		infoPanel.add(sizeTextField, gridBagConstraints);

		provider.registerHelp(sizeTextField, "Size");

		sizeTextField.setInputVerifier(new InputVerifier() {
			@Override
			public boolean verify(JComponent input) {
				return decodeUnsignedIntEntry(sizeTextField, "structure size", true) >= 0;
			}
		});

		sizeTextField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ESCAPE) {
					e.consume();
					// revert to model state when escape is hit
					setCompositeSize(model.getLength());
				}
			}
		});

		sizeTextField.addTextEntryStatusListener(c -> provider.contextChanged());

		sizeTextField.addActionListener(e -> updatedStructureSize());

		sizeTextField.addFocusListener(new FocusAdapter() {
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
		sizeTextField.setEnabled(editable);
		if (editable) {
			// editable - use same background as description field
			sizeTextField.setBackground(descriptionTextField.getBackground());
		}
		else {
			// not editable - use same background as panel
			sizeTextField.setBackground(getBackground());
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

		if (sizeTextField.getTextEntryStatus() != CHANGED) {
			return;
		}

		int size = decodeUnsignedIntEntry(sizeTextField, "structure size", true);
		if (size < 0) {
			return;
		}

		updatingSize = true;
		try {
			if (size < model.getLength()) {
				// Decreasing structure length.
				// Verify that user really wants this.
				String question = "The size field was changed to " + size + " bytes.\n" +
					"Do you really want to truncate " + model.getCompositeName() + "?";
				String title = "Truncate " + model.getTypeName() + " In Editor?";
				int response =
					OptionDialog.showYesNoDialogWithNoAsDefaultButton(this, title, question);
				if (response != OptionDialog.YES_OPTION) {
					compositeInfoChanged();
					return;
				}
			}
			((StructureEditorModel) model).setStructureSize(size);
		}
		finally {
			updatingSize = false;
		}
		compositeInfoChanged();
	}

	private void chooseExplicitAlign() {
		if (((CompEditorModel) model).getAlignmentType() != AlignmentType.EXPLICIT) {
			Composite viewComposite = ((CompEditorModel) model).viewComposite;
			int defaultValue = 1;
			if (viewComposite.isPackingEnabled()) {
				defaultValue = viewComposite.getDataOrganization().getMachineAlignment();
			}
			((CompEditorModel) model).setAlignmentType(AlignmentType.EXPLICIT, defaultValue);
		}
		explicitAlignTextField.selectAll();
		explicitAlignTextField.requestFocus();
	}

	private int decodeUnsignedIntEntry(JTextField textField, String type, boolean zeroAllowed) {
		model.clearStatus();
		String valueStr = textField.getText().trim();
		if (StringUtils.isEmpty(valueStr)) {
			model.setStatus("Missing " + type + ".", false);
			return -1;
		}
		try {
			int value = Integer.decode(valueStr);
			if (value < 0) {
				model.setStatus("Negative " + type + " not permitted.", true);
				return -1;
			}
			if (value == 0 && !zeroAllowed) {
				model.setStatus("Zero " + type + " not permitted.", true);
				return -1;
			}
			model.setStatus(null);
			return value;
		}
		catch (NumberFormatException e1) {
			model.setStatus("Invalid " + type + " \"" + valueStr + "\".", true);
			return -1;
		}
	}

	private void updateEntryAcceptanceStatus() {
		Swing.runLater(() -> {
			if (!hasInvalidEntry() && hasUncomittedEntry()) {
				setStatus("Hit <Enter> key in edit field to accept entry");
			}
		});
	}

	@Override
	protected boolean hasUncomittedEntry() {
		return nameTextField.getTextEntryStatus() == CHANGED ||
			descriptionTextField.getTextEntryStatus() == CHANGED ||
			sizeTextField.getTextEntryStatus() == CHANGED ||
			explicitAlignTextField.getTextEntryStatus() == CHANGED ||
			explicitPackingTextField.getTextEntryStatus() == CHANGED;
	}

	@Override
	protected boolean hasInvalidEntry() {
		return nameTextField.getTextEntryStatus() == INVALID ||
			descriptionTextField.getTextEntryStatus() == INVALID ||
			sizeTextField.getTextEntryStatus() == INVALID ||
			explicitAlignTextField.getTextEntryStatus() == INVALID ||
			explicitPackingTextField.getTextEntryStatus() == INVALID;
	}

	@Override
	protected void comitEntryChanges() {
		if (nameTextField.getTextEntryStatus() == CHANGED) {
			updatedName();
		}
		else if (descriptionTextField.getTextEntryStatus() == CHANGED) {
			updatedDescription();
		}
		else if (sizeTextField.getTextEntryStatus() == CHANGED) {
			updatedStructureSize();
		}
		else if (explicitAlignTextField.getTextEntryStatus() == CHANGED) {
			adjustExplicitMinimumAlignmentValue();
		}
		else if (explicitPackingTextField.getTextEntryStatus() == CHANGED) {
			adjustPackingValue();
		}
	}

	/**
	 * Gets called when the user updates the name.
	 */
	protected void updatedName() {

		if (!nameTextField.isShowing()) {
			return;
		}

		if (nameTextField.getTextEntryStatus() != CHANGED) {
			return;
		}

		// Adjust the value.
		String newName = nameTextField.getText().trim();
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
			setCompositeName(originalDtName);
			model.setStatus("Name is required. So original name has been restored.");
			return;
		}

		setCompositeName(newName);

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

		if (descriptionTextField.getTextEntryStatus() != CHANGED) {
			return;
		}

		String newValue = this.descriptionTextField.getText().trim();
		if (!newValue.equals(model.getDescription())) {
			model.setDescription(newValue);
			setDescription(newValue);
		}
	}

	/**
	 * Returns the currently displayed structure category name.
	 * @return the name
	 */
	public String getCategoryName() {
		return categoryNameLabel.getText();
	}

	/**
	 * Sets the currently displayed structure category name.
	 *
	 * @param name
	 *            the new category name
	 */
	public void setCategoryName(String name) {
		categoryNameLabel.setText(name);
	}

	/**
	 * Sets the currently displayed structure name which matches the model state
	 *
	 * @param name the new name
	 */
	private void setCompositeName(String name) {
		nameTextField.setText(name);
		nameTextField.setDefaultValue(name);
		nameTextField.setIsError(false);
		setStatus("");
	}

	/**
	 * Sets the currently displayed structure description which matches the model state
	 *
	 * @param description the new description
	 */
	private void setDescription(String description) {
		descriptionTextField.setText(description);
		descriptionTextField.setDefaultValue(description);
		descriptionTextField.setIsError(false);
		setStatus("");
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
		explicitAlignTextField.setDefaultValue(minimumAlignmentStr);
		explicitAlignTextField.setIsError(false);
	}

	/**
	 * Updates the GUI display of the actual alignment value.
	 */
	public void refreshGUIActualAlignmentValue() {
		int actualAlignment = ((CompEditorModel) model).getActualAlignment();
		String alignmentStr =
			model.showHexNumbers ? CompositeViewerModel.getHexString(actualAlignment, true)
					: Integer.toString(actualAlignment);
		actualAlignmentValueLabel.setText(alignmentStr);
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
	private void setCompositeSize(int size) {
		boolean sizeIsEditable = ((CompEditorModel) model).isSizeEditable();
		if (sizeTextField.isEditable() != sizeIsEditable) {
			setSizeEditable(sizeIsEditable);
		}
		String sizeStr = model.showHexNumbers ? CompositeViewerModel.getHexString(size, true)
				: Integer.toString(size);
		sizeTextField.setText(sizeStr);
		sizeTextField.setDefaultValue(sizeStr);
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
		// stub
	}

	/**
	 * A simple class that allows clients to focus other components when the up or down arrows keys
	 * are pressed
	 */
	private class UpAndDownKeyListener extends KeyAdapter {

		private JRadioButton previousComponent;
		private JRadioButton nextComponent;

		UpAndDownKeyListener(JRadioButton previousComponent, JRadioButton nextComponent) {
			this.previousComponent = previousComponent;
			this.nextComponent = nextComponent;
		}

		@Override
		public void keyPressed(KeyEvent e) {

			if (e.isConsumed()) {
				return;
			}

			int code = e.getKeyCode();
			if (code == KeyEvent.VK_UP) {
				// We need to run later due to focusLost() listener on the text field that will 
				// interfere with the selected state of our newly selected button
				previousComponent.requestFocusInWindow();
				Swing.runLater(() -> previousComponent.setSelected(true));
				e.consume();
			}
			else if (code == KeyEvent.VK_DOWN) {
				// We need to run later due to focusLost() listener on the text field that will 
				// interfere with the selected state of our newly selected button
				nextComponent.requestFocusInWindow();
				Swing.runLater(() -> nextComponent.setSelected(true));
				e.consume();
			}
		}
	}

}
