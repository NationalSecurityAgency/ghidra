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
package ghidra.app.plugin.core.references;

import java.awt.*;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import org.jdom.Element;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;

public class EditReferenceDialog extends DialogComponentProvider {

	static final int PREFERRED_PANEL_HEIGHT = 190;
	static final int PREFERRED_PANEL_WIDTH = 450;

	private static final HelpLocation ADD_HELP = new HelpLocation("ReferencesPlugin", "addRef");
	private static final HelpLocation EDIT_HELP = new HelpLocation("ReferencesPlugin", "editRef");

	private ReferencesPlugin plugin;
	private InstructionPanel instrPanel;

	private JRadioButton memRefChoice;
	private JRadioButton extRefChoice;
	private JRadioButton stackRefChoice;
	private JRadioButton regRefChoice;

	private JPanel bottomPanel;
	private CardLayout bottomPanelLayout;

	private EditMemoryReferencePanel memRefPanel;
	private EditExternalReferencePanel extRefPanel;
	private EditStackReferencePanel stackRefPanel;
	private EditRegisterReferencePanel regRefPanel;
	private EditReferencePanel activeRefPanel;

	private boolean initializing;

	public EditReferenceDialog(ReferencesPlugin plugin) {
		super("Edit Reference", true);
		this.plugin = plugin;
		addWorkPanel(buildMainPanel());
		addApplyButton();
		addCancelButton();

		setDefaultButton(applyButton);
	}

	/**
	 * Dispose of this dialog.
	 */
	public void dispose() {
		close();
		cleanup();
	}

	/**
	 * Returns the current code unit displayed.
	 */
	CodeUnit getCurrentCodeUnit() {
		return instrPanel.getCurrentCodeUnit();
	}

	private void cleanup() {
		memRefPanel.cleanup();
		extRefPanel.cleanup();
		stackRefPanel.cleanup();
		regRefPanel.cleanup();
	}

	private JComponent buildMainPanel() {

		JPanel topPanel = new JPanel(new BorderLayout());

		instrPanel = new InstructionPanel(5, 5, 5, 5, null, plugin, new InstructionPanelListener() {
			@Override
			public boolean dropSupported() {
				return false;
			}

			@Override
			public void operandSelected(int opIndex, int subIndex) {
				if (!initializing) {
					setAddOpIndex(opIndex, subIndex);
				}
			}

			@Override
			public void selectionDropped(AddressSetView set, CodeUnit cu, int opIndex) {
				throw new UnsupportedOperationException();
			}
		});
		topPanel.add(instrPanel, BorderLayout.NORTH);

		JPanel refTypePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
		refTypePanel.setBorder(new TitledBorder(new EtchedBorder(), "Type of Reference"));
		ChangeListener refChoiceListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				Object src = e.getSource();
				if (src instanceof JRadioButton) {
					JRadioButton refChoiceButton = (JRadioButton) src;
					if (refChoiceButton.isSelected()) {
						refChoiceActivated(refChoiceButton);
					}
				}
			}
		};

		memRefChoice = new GRadioButton("Memory");
		memRefChoice.addChangeListener(refChoiceListener);
		extRefChoice = new GRadioButton("External");
		extRefChoice.addChangeListener(refChoiceListener);
		stackRefChoice = new GRadioButton("Stack");
		stackRefChoice.addChangeListener(refChoiceListener);
		regRefChoice = new GRadioButton("Register");
		regRefChoice.addChangeListener(refChoiceListener);

		ButtonGroup refChoices = new ButtonGroup();
		refChoices.add(memRefChoice);
		refChoices.add(extRefChoice);
		refChoices.add(stackRefChoice);
		refChoices.add(regRefChoice);

		refTypePanel.add(memRefChoice);
		refTypePanel.add(extRefChoice);
		refTypePanel.add(stackRefChoice);
		refTypePanel.add(regRefChoice);

		topPanel.add(refTypePanel, BorderLayout.CENTER);

		Border panelBorder = new EmptyBorder(5, 10, 5, 10);
		memRefPanel = new EditMemoryReferencePanel(plugin);
		memRefPanel.setBorder(panelBorder);
		extRefPanel = new EditExternalReferencePanel(plugin);
		extRefPanel.setBorder(panelBorder);
		stackRefPanel = new EditStackReferencePanel(plugin);
		stackRefPanel.setBorder(panelBorder);
		regRefPanel = new EditRegisterReferencePanel(plugin);
		regRefPanel.setBorder(panelBorder);

		bottomPanelLayout = new CardLayout();
		bottomPanel = new JPanel(bottomPanelLayout);
		bottomPanel.setFocusCycleRoot(true);
		bottomPanel.setPreferredSize(new Dimension(PREFERRED_PANEL_WIDTH, PREFERRED_PANEL_HEIGHT));
		bottomPanel.setBorder(new EmptyBorder(0, 2, 0, 2));

		bottomPanel.add(memRefPanel, memRefPanel.getName());
		bottomPanel.add(extRefPanel, extRefPanel.getName());
		bottomPanel.add(stackRefPanel, stackRefPanel.getName());
		bottomPanel.add(regRefPanel, regRefPanel.getName());

		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.add(topPanel, BorderLayout.NORTH);
		workPanel.add(bottomPanel, BorderLayout.CENTER);

		return workPanel;
	}

	private void setAddOpIndex(int opIndex, int subIndex) {

		CodeUnit cu = instrPanel.getCurrentCodeUnit();
		Program p = cu.getProgram();
		boolean inFunction =
			(p.getFunctionManager().getFunctionContaining(cu.getMinAddress()) != null);
		Reference[] refs = p.getReferenceManager().getReferencesFrom(cu.getMinAddress(), opIndex);
		Address existingRefAddr = refs.length != 0 ? refs[0].getToAddress() : null;

		if (!memRefPanel.initialize(cu, opIndex, subIndex)) {
			throw new AssertException("Memory reference must always be permitted");
		}

		memRefChoice.setEnabled(true);
		extRefChoice.setEnabled(extRefPanel.initialize(cu, opIndex, subIndex));
		stackRefChoice.setEnabled(inFunction && stackRefPanel.initialize(cu, opIndex, subIndex));
		regRefChoice.setEnabled(inFunction && regRefPanel.initialize(cu, opIndex, subIndex));

		memRefChoice.setSelected(true);
		if (existingRefAddr != null) {
			if (existingRefAddr.isStackAddress()) {
				if (stackRefChoice.isEnabled()) {
					stackRefChoice.setSelected(true);
				}
			}
			else if (existingRefAddr.isRegisterAddress()) {
				if (regRefChoice.isEnabled()) {
					regRefChoice.setSelected(true);
				}
			}
			else if (existingRefAddr.isExternalAddress()) {
				if (extRefChoice.isEnabled()) {
					extRefChoice.setSelected(true);
				}
			}
		}
		else {
			if (stackRefChoice.isEnabled() && stackRefPanel.isValidStackRef()) {
				stackRefChoice.setSelected(true);
			}
			else if (regRefChoice.isEnabled()) {
				regRefChoice.setSelected(true);
			}
		}
	}

	private void refChoiceActivated(JRadioButton refChoiceButton) {
		if (refChoiceButton == memRefChoice) {
			activeRefPanel = memRefPanel;
		}
		else if (refChoiceButton == stackRefChoice) {
			activeRefPanel = stackRefPanel;
		}
		else if (refChoiceButton == regRefChoice) {
			activeRefPanel = regRefPanel;
		}
		else if (refChoiceButton == extRefChoice) {
			activeRefPanel = extRefPanel;
		}
		bottomPanelLayout.show(bottomPanel, activeRefPanel.getName());
		activeRefPanel.requestFocus();
	}

	public void initDialog(CodeUnit cu, int opIndex, int subIndex, Reference ref) {

		initializing = true;

		instrPanel.setCodeUnitLocation(cu, opIndex, subIndex, ref != null);

		if (ref != null) {
			configureEditReference(cu, ref);
		}
		else {
			configureAddReference(opIndex, subIndex);
		}

		initializing = false;
		activeRefPanel.requestFocus();
	}

	private void configureAddReference(int opIndex, int subIndex) {
		setTitle("Add Reference");
		setHelpLocation(ADD_HELP);

		applyButton.setText("Add");

		setAddOpIndex(opIndex, subIndex);
	}

	private void configureEditReference(CodeUnit cu, Reference ref) {
		setTitle("Edit Reference");
		setHelpLocation(EDIT_HELP);

		applyButton.setText("Update");

		memRefChoice.setEnabled(false);
		extRefChoice.setEnabled(false);
		stackRefChoice.setEnabled(false);
		regRefChoice.setEnabled(false);

		Address toAddress = ref.getToAddress();
		if (toAddress.isRegisterAddress() || cu.getProgram().getRegister(toAddress) != null) {
			regRefPanel.initialize(cu, ref);
			regRefChoice.setSelected(true);
			regRefChoice.setEnabled(true);
			if (toAddress.isMemoryAddress()) {
				memRefPanel.initialize(cu, ref);
				memRefChoice.setEnabled(true);
			}
		}
		else if (toAddress.isStackAddress()) {
			stackRefPanel.initialize(cu, ref);
			stackRefChoice.setSelected(true);
			stackRefChoice.setEnabled(true);
		}
		else if (toAddress.isMemoryAddress()) {
			memRefPanel.initialize(cu, ref);
			memRefChoice.setSelected(true);
			memRefChoice.setEnabled(true);
		}
		else if (toAddress.isExternalAddress()) {
			extRefPanel.initialize(cu, ref);
			extRefChoice.setSelected(true);
			extRefChoice.setEnabled(true);
		}
		else {
			throw new AssertException("Unknown address type");
		}
	}

	@Override
	protected void applyCallback() {
		if (activeRefPanel.applyReference()) {
			close();
			cleanup();
		}
	}

	@Override
	protected void cancelCallback() {
		close();
		cleanup();
	}

	void readDataState(SaveState saveState) {
		Element element = saveState.getXmlElement("MemoryReferencePanelState");
		if (element != null) {
			memRefPanel.readXmlDataState(element);
		}
	}

	void writeDataState(SaveState saveState) {
		Element element = new Element("MemoryReferencePanelState");
		memRefPanel.writeXmlDataState(element);
		saveState.putXmlElement("MemoryReferencePanelState", element);
	}

}
