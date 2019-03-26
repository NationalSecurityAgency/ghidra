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
package ghidra.app.plugin.core.instructionsearch.model;

import java.awt.Color;
import java.util.HashSet;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.border.Border;

import ghidra.app.plugin.core.instructionsearch.ui.AbstractInstructionTable.OperandState;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTable;

/**
 * Defines the contents of a single cell in the {@link InstructionTable}.
 * <p>
 * To be notified of table changes, clients can subscribe to this object using
 * the register() method.
 */
public class InstructionTableDataObject {

	/**
	 * Set of clients who wish to be notified of changes to the
	 * {@link InstructionTable}. We use the observer pattern, with this class
	 * being an observable. Clients subscribe to changes on this class and will
	 * be notified via callback when they occur.
	 * <p>
	 * This is static since all data objects will have the same list of
	 * observers
	 */
	private Set<InstructionTableObserver> observers = new HashSet<InstructionTableObserver>();

	// The text displayed in the cell.
	private String data;

	// Some cell attributes.
	private Color backgroundColor;
	private Color foregroundColor;
	private int fontStyle;

	// The border style of the cell.  This is used to facilitate the 3D look of the 
	// cells (bevel-styling).
	private Border border;

	// The state of the object; this describes whether the cell is in a masked or
	// unmasked state, or neither (NA).
	private OperandState state;

	// True if this data object represents an instruction (and not an undefined data item or
	// string).
	private boolean isInstruction;

	// Stores information about the operand for this cell (if it's an operand); if the
	// cell represents a mnemonic then this does not apply.
	private OperandMetadata operandCase;

	private static final Color BACKGROUND_COLOR = new Color(237, 243, 254);
	private static final Color BACKGROUND_COLOR_DARKER = new Color(188, 212, 254);
	private static final Color BACKGROUND_COLOR_NON_INSTRUCTION = new Color(255, 242, 214);
	private static final Color BACKGROUND_COLOR_DARKER_NON_INSTRUCTION = new Color(203, 186, 150);
	private static final Color PANEL_COLOR = new Color(214, 217, 223);

	/**
	 * Constructor.
	 * 
	 * @param data the text to be displayed
	 * @param isInstruction true if the code unit is an instruction, false if
	 *            data or something else.
	 * @param state the initial state of the item
	 */
	public InstructionTableDataObject(String data, boolean isInstruction, OperandState state) {
		this.data = data;
		this.isInstruction = isInstruction;
		setState(state, false);
	}

	/**
	 * Toggles the state of the cell between masked/unmasked. A notification is
	 * issued to subscribers if there is a state change.
	 * 
	 */
	public void toggleMaskState() {
		switch (state) {
			case MASKED:
				setState(OperandState.NOT_MASKED, false);
				notifySubscribers();
				break;
			case NOT_MASKED:
				setState(OperandState.MASKED, false);
				notifySubscribers();
				break;
			case NA:
				// do nothing
				break;
			case PREVIEW:
				// do nothing
				break;
		}
	}

	/**
	 * Changes the state of the operand or mnemonic.
	 * 
	 * @param state the new operand state
	 * @param update if true, a notification is issued to subscribers
	 */
	public void setState(OperandState state, boolean update) {
		this.state = state;

		switch (state) {
			case MASKED:
				backgroundColor =
					isInstruction ? BACKGROUND_COLOR : BACKGROUND_COLOR_NON_INSTRUCTION;
				foregroundColor = Color.BLACK;
				border = BorderFactory.createLoweredSoftBevelBorder();
				break;
			case NOT_MASKED:
				backgroundColor = isInstruction ? BACKGROUND_COLOR_DARKER
						: BACKGROUND_COLOR_DARKER_NON_INSTRUCTION;
				foregroundColor = Color.BLACK;
				border = BorderFactory.createRaisedSoftBevelBorder();
				break;
			case NA:
				backgroundColor = PANEL_COLOR;
				break;
			case PREVIEW:
				backgroundColor =
					isInstruction ? BACKGROUND_COLOR : BACKGROUND_COLOR_NON_INSTRUCTION;
				break;
		}

		if (update) {
			notifySubscribers();
		}
	}

	/**
	 * Subscribes the given observer to be notified of changes to this object.
	 */
	public void register(InstructionTableObserver observer) {
		observers.add(observer);
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	public Color getBackgroundColor() {
		return backgroundColor;
	}

	public Color getForegroundColor() {
		return foregroundColor;
	}

	public int getFontStyle() {
		return fontStyle;
	}

	public OperandState getState() {
		return state;
	}

	public Border getBorder() {
		return border;
	}

	public OperandMetadata getOperandCase() {
		return operandCase;
	}

	public void setOperandCase(OperandMetadata operandCase) {
		this.operandCase = operandCase;
	}

	public boolean isInstruction() {
		return this.isInstruction;
	}

	/**
	 * Override of the toString method to just print the contents of the cell.
	 */
	@Override
	public String toString() {
		return this.data;
	}

	/**
	 * Fires off notifications to all subscribers that the state of the table
	 * has changed.
	 */
	private void notifySubscribers() {
		for (InstructionTableObserver obs : observers) {
			if (obs != null) {
				obs.changed();
			}
		}
	}
}
