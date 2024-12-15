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
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.dnd.*;
import java.awt.event.*;
import java.io.IOException;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.action.DockingAction;
import docking.actions.KeyBindingUtils;
import docking.dnd.DropTgtAdapter;
import docking.dnd.Droppable;
import docking.widgets.label.GDLabel;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors;
import generic.theme.Gui;
import ghidra.app.util.*;
import ghidra.app.util.viewer.field.BrowserCodeUnitFormat;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;

class InstructionPanel extends JPanel implements ChangeListener {
	private static Color FOCUS_COLOR = new GColor("color.palette.yellow");
	private static final int BORDER_SIZE = 2;
	private static final Border EMPTY_BORDER =
		new EmptyBorder(BORDER_SIZE, BORDER_SIZE, BORDER_SIZE, BORDER_SIZE);
	private static final Border ETCHED_BORDER = new EtchedBorder();

	private final static Color NOT_IN_MEMORY_COLOR = Colors.ERROR;
	private final static Color DEFAULT_FG_COLOR = Colors.FOREGROUND;

	private static final DataFlavor[] ACCEPTABLE_DROP_FLAVORS =
		new DataFlavor[] { SelectionTransferable.localProgramSelectionFlavor };

	private MouseListener mouseListener = new LabelMouseListener();
	private boolean locked;

	private DockingAction goHomeAction;
	private JLabel addressLabel;
	private JLabel mnemonicLabel;
	private JLabel[] operandLabels;
	private DropTarget[] dropTargets; // 0: mnemonic, >= 1: operands
	private JPanel innerPanel;
	private int activeIndex;
	private int activeSubIndex;
	private CodeUnit currentCodeUnit;
	private BrowserCodeUnitFormat cuFormat;
	private SymbolInspector symbolInspector;
	private Memory memory;
	private InstructionPanelListener listener;

	private boolean dropSupported;
	private DropTgtAdapter dropTargetAdapter;
	private Droppable dropHandler = new InstructionPanelDroppable();
	private int nOperands;

	InstructionPanel(int topPad, int leftPad, int bottomPad, int rightPad,
			DockingAction goHomeAction, ReferencesPlugin plugin,
			InstructionPanelListener listener) {
		super(new BorderLayout());
		this.dropSupported = listener != null ? listener.dropSupported() : false;
		this.goHomeAction = goHomeAction;
		this.symbolInspector = plugin.getSymbolInspector();
		this.cuFormat = plugin.getCodeUnitFormat();
		this.listener = listener;
		create(topPad, leftPad, bottomPad, rightPad);
	}

	private int getNextIndex() {
		if (operandLabels.length == 0) {
			return ReferenceManager.MNEMONIC;
		}
		if (activeIndex == ReferenceManager.MNEMONIC) {
			return 0;
		}
		if (activeIndex < nOperands - 1) {
			return activeIndex + 1;
		}
		return ReferenceManager.MNEMONIC;
	}

	private int getPreviousIndex() {
		if (operandLabels.length == 0) {
			return ReferenceManager.MNEMONIC;
		}
		if (activeIndex == ReferenceManager.MNEMONIC) {
			return nOperands - 1;
		}
		if (activeIndex > 0) {
			return activeIndex - 1;
		}
		return ReferenceManager.MNEMONIC;
	}

	CodeUnit getCurrentCodeUnit() {
		return currentCodeUnit;
	}

	@Override
	public void stateChanged(ChangeEvent e) {
		updateActiveIndex(activeIndex, activeSubIndex);
	}

	void setCodeUnitLocation(CodeUnit cu, int opIndex, int subIndex, boolean locked) {
		if (cu != null) {
			this.locked = locked;
			addressLabel.setText(cu.getMinAddress().toString());
			memory = cu.getProgram().getMemory();
			cuFormat.addChangeListener(this);
		}
		else {
			cuFormat.removeChangeListener(this);
			this.locked = false;
			addressLabel.setText("");
			memory = null;
		}
		currentCodeUnit = cu;
		activeIndex = ReferenceManager.MNEMONIC - 1; // force updateLabels to work
		updateActiveIndex(opIndex, subIndex);
		updateDropTargets(cu != null ? cu.getNumOperands() : -1);
	}

	void setSelectedOpIndex(int index, int subIndex) {
		updateActiveIndex(index, subIndex);
	}

	int getSelectedOpIndex() {
		return activeIndex;
	}

	int getSelectedSubOpIndex() {
		return activeSubIndex;
	}

	/** 
	 * Create the components for this panel.
	 */
	private void create(int topPad, int leftPad, int bottomPad, int rightPad) {
		Border border = new TitledBorder(new EtchedBorder(), "Source");
		setBorder(border);

		addressLabel = new GDLabel("FFFFFFFF"); // use a default
		Gui.registerFont(addressLabel, "font.monospaced");
		addressLabel.setName("addressLabel");

		mnemonicLabel = new GDLabel("movl");
		Gui.registerFont(mnemonicLabel, "font.monospaced");
		mnemonicLabel.setName("mnemonicLabel");
		mnemonicLabel.addMouseListener(mouseListener);

		operandLabels = new JLabel[Program.MAX_OPERANDS];
		for (int i = 0; i < operandLabels.length; i++) {
			operandLabels[i] = new GDLabel("%ebp, ");
			operandLabels[i].setName("operandLabels[" + i + "]");
			operandLabels[i].addMouseListener(mouseListener);
			Gui.registerFont(operandLabels[i], "font.monospaced");
		}

		innerPanel = new JPanel();
		BoxLayout bl = new BoxLayout(innerPanel, BoxLayout.X_AXIS);
		innerPanel.setLayout(bl);
		setName("Instruction Panel");
		setToolTipText("This component selects which instruction piece is active for this dialog");
		innerPanel.getAccessibleContext()
				.setAccessibleDescription("Use left or right arrows to choose which mnemonic or" +
					" operand piece this dialog applies to");
		updateAccessibleInfo();

		if (goHomeAction != null) {
			Action action = KeyBindingUtils.adaptDockingActionToNonContextAction(goHomeAction);
			JButton homeButton = new JButton(action);
			homeButton.setText(null);
			homeButton.setMargin(new Insets(0, 0, 0, 0));
			innerPanel.add(Box.createHorizontalStrut(5));
			add(homeButton, BorderLayout.WEST);
		}

		innerPanel.add(Box.createHorizontalStrut(5));
		innerPanel.add(addressLabel);
		innerPanel.add(Box.createHorizontalStrut(20));
		innerPanel.add(mnemonicLabel);
		innerPanel.add(Box.createHorizontalStrut(10));
		innerPanel.setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));

		for (JLabel operandLabel : operandLabels) {
			innerPanel.add(operandLabel);
			innerPanel.add(Box.createHorizontalStrut(5));
		}

		add(innerPanel, BorderLayout.CENTER);

		if (dropSupported) {

			dropTargetAdapter = new DropTgtAdapter(dropHandler, DnDConstants.ACTION_COPY_OR_MOVE,
				ACCEPTABLE_DROP_FLAVORS);

			// Setup drop targets for mnemonic and each operand label
			dropTargets = new DropTarget[Program.MAX_OPERANDS + 1];
			dropTargets[0] = new DropTarget(mnemonicLabel, DnDConstants.ACTION_COPY_OR_MOVE,
				dropTargetAdapter, true);
			dropTargets[0].setActive(false);
			for (int i = 1; i < dropTargets.length; i++) {
				dropTargets[i] = new DropTarget(operandLabels[i - 1],
					DnDConstants.ACTION_COPY_OR_MOVE, dropTargetAdapter, true);
				dropTargets[i].setActive(false);
			}

		}
		innerPanel.setFocusable(true);
		innerPanel.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				switch (e.getKeyCode()) {
					case KeyEvent.VK_LEFT:
						updateActiveIndex(getPreviousIndex(), -1);
						e.consume();
						break;
					case KeyEvent.VK_RIGHT:
						updateActiveIndex(getNextIndex(), -1);
						e.consume();
						break;
				}
			}
		});
		innerPanel.addFocusListener(new FocusListener() {

			@Override
			public void focusLost(FocusEvent e) {
				innerPanel.setBorder(BorderFactory.createEmptyBorder(1, 1, 1, 1));
			}

			@Override
			public void focusGained(FocusEvent e) {
				innerPanel.setBorder(BorderFactory.createLineBorder(FOCUS_COLOR, 1));
			}
		});

	}

	/**
	 * Enable drop on specified number of operands.
	 * A value of -1 will disable all drop targets.
	 * @param numOperands the number of operands
	 */
	private void updateDropTargets(int numOperands) {
		++numOperands;
		if (dropSupported) {
			for (int i = 0; i < dropTargets.length; i++) {
				dropTargets[i].setActive(i < numOperands);
			}
		}
	}

	/**
	 * Method updateLabels.
	 */
	private void updateActiveIndex(int index, int subIndex) {
		int prevIndex = activeIndex;
		activeIndex = index;
		activeSubIndex = subIndex;
		updateLabels();
		updateAccessibleInfo();
		if (activeIndex != prevIndex && listener != null) {
			listener.operandSelected(activeIndex, activeSubIndex);
		}
		updateAccessibleInfo();
	}

	private void updateAccessibleInfo() {
		String accessibleName = "Instruction Reference Panel";
		if (activeIndex < 0) {
			accessibleName += ", mnemonic selected";
		}
		else {
			accessibleName += ", operand " + activeIndex + " selected";
		}
		innerPanel.getAccessibleContext().setAccessibleName(accessibleName);
	}

	private void updateLabels() {
		for (JLabel operandLabel : operandLabels) {
			operandLabel.setText("");
			operandLabel.setBorder(EMPTY_BORDER);
			operandLabel.setBackground(getParent().getBackground());
		}
		if (currentCodeUnit != null) {

			nOperands = currentCodeUnit.getNumOperands();
			for (int i = 0; i < nOperands; i++) {
				String opRep = cuFormat.getOperandRepresentationString(currentCodeUnit, i);
				if (i < nOperands - 1) {
					opRep = opRep + ",";
				}
				setOperandAttributes(i, opRep);
			}

			setMnemonicAttributes(currentCodeUnit.getMnemonicString());
		}
		else {
			mnemonicLabel.setText("");
			mnemonicLabel.setBorder(EMPTY_BORDER);
			mnemonicLabel.setBackground(getParent().getBackground());
		}
		innerPanel.invalidate();
		repaint();
	}

	/**
	 * Determine the color to use to render the specified operand
	 */
	private Color getOperandColor(int opIndex) {

		Program program = currentCodeUnit.getProgram();

		// rely on primary reference if available as this should be the basis of 
		// the formatted operand representation.
		Reference ref = currentCodeUnit.getPrimaryReference(opIndex);
		Address refAddr = ref != null ? ref.getToAddress() : currentCodeUnit.getAddress(opIndex);

		if (refAddr == null) {
			return DEFAULT_FG_COLOR;
		}

		if (refAddr.isMemoryAddress() && !program.getMemory().contains(refAddr)) {
			return NOT_IN_MEMORY_COLOR;
		}

		SymbolTable st = program.getSymbolTable();
		Symbol sym = st.getSymbol(ref);
		if (sym != null) {
			return symbolInspector.getColor(sym);
		}

		return DEFAULT_FG_COLOR;
	}

	/**
	 * Set the operand text and attributes
	 */
	private void setOperandAttributes(int opIndex, String operandText) {

		operandLabels[opIndex].setText(operandText);
		operandLabels[opIndex].setForeground(getOperandColor(opIndex));

		if (activeIndex == opIndex) {
			operandLabels[opIndex].setBorder(ETCHED_BORDER);
			operandLabels[opIndex].setBackground(EditReferencesProvider.BG_COLOR_ACTIVE_OPERAND);
			operandLabels[opIndex].setOpaque(true);
		}
		else {
			operandLabels[opIndex].setBackground(getParent().getBackground());
			operandLabels[opIndex].setBorder(EMPTY_BORDER);
			operandLabels[opIndex].setOpaque(false);
		}
	}

	/**
	 * Set the mnemonic text and attributes
	 */
	private void setMnemonicAttributes(String mnemonicText) {

		mnemonicLabel.setText(mnemonicText);
		mnemonicLabel.setForeground(DEFAULT_FG_COLOR);

		if (activeIndex == ReferenceManager.MNEMONIC) {
			mnemonicLabel.setBackground(EditReferencesProvider.BG_COLOR_ACTIVE_OPERAND);
			mnemonicLabel.setBorder(ETCHED_BORDER);
			mnemonicLabel.setOpaque(true);
		}
		else {
			mnemonicLabel.setBackground(getParent().getBackground());
			mnemonicLabel.setBorder(EMPTY_BORDER);
			mnemonicLabel.setOpaque(false);
		}
	}

	private int getLabelIndex(JLabel label) {
		for (int i = 0; i < operandLabels.length; i++) {
			if (operandLabels[i] == label) {
				return i;
			}
		}
		return ReferenceManager.MNEMONIC;
	}

	private class LabelMouseListener extends MouseAdapter {
		@Override
		public void mouseEntered(MouseEvent e) {
			if (!locked) {
				JLabel label = (JLabel) e.getSource();
				label.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
			}
		}

		@Override
		public void mouseExited(MouseEvent e) {
			JLabel label = (JLabel) e.getSource();
			label.setCursor(Cursor.getDefaultCursor());
		}

		@Override
		public void mousePressed(MouseEvent e) {
			if (!locked) {
				JLabel label = (JLabel) e.getSource();
				updateActiveIndex(getLabelIndex(label), -1);
			}
		}
	}

	private class InstructionPanelDroppable implements Droppable {

		@Override
		public boolean isDropOk(DropTargetDragEvent e) {

			Component targetComp = e.getDropTargetContext().getComponent();
			if (!(targetComp instanceof JLabel)) {
				return false;
			}

			updateActiveIndex(getLabelIndex((JLabel) targetComp), -1);

			try {
				Object data = e.getTransferable()
						.getTransferData(SelectionTransferable.localProgramSelectionFlavor);
				AddressSetView view = ((SelectionTransferData) data).getAddressSet();
				if (memory.contains(view)) {
					return true;
				}
			}
			catch (UnsupportedFlavorException e1) {
				// return false
			}
			catch (IOException e1) {
				// return false
			}
			return false;
		}

		@Override
		public void add(Object obj, DropTargetDropEvent e, DataFlavor f) {
			AddressSetView view = ((SelectionTransferData) obj).getAddressSet();
			if (view.getNumAddressRanges() == 0) {
				return;
			}
			listener.selectionDropped(view, currentCodeUnit, activeIndex);
		}

	}
}
