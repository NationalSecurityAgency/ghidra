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

import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.layout.PairLayout;

class EditStackReferencePanel extends EditReferencePanel {

	private static final RefType[] STACK_REF_TYPES = RefTypeFactory.getStackRefTypes();

	private ReferencesPlugin plugin;

	// Fields required for ADD
	private CodeUnit fromCodeUnit;
	private int opIndex;

	// Fields required for EDIT
	private StackReference editRef;

	private JTextField stackOffset;
	private GhidraComboBox<RefType> refTypes;

	private boolean isValidStackRef;
	private boolean isValidState;

	EditStackReferencePanel(ReferencesPlugin plugin) {
		super("STACK");
		this.plugin = plugin;
		buildPanel();
	}

	private void buildPanel() {
		setLayout(new PairLayout(10, 10, 160));
		setBorder(new EmptyBorder(0, 5, 5, 5));

		stackOffset = new JTextField();

		refTypes = new GhidraComboBox<>(STACK_REF_TYPES);

		add(new GLabel("Stack Offset:", SwingConstants.RIGHT));
		add(stackOffset);
		add(new GLabel("Ref-Type:", SwingConstants.RIGHT));
		add(refTypes);
	}

	private void populateRefTypes(RefType adhocType) {
		refTypes.clearModel();
		for (RefType element : STACK_REF_TYPES) {
			if (adhocType == element) {
				adhocType = null;
			}
			refTypes.addItem(element);
		}
		if (adhocType != null) {
			refTypes.addItem(adhocType);
		}
	}

	boolean isValidStackRef() {
		return isValidStackRef;
	}

	@Override
	public void initialize(CodeUnit fromCu, Reference editReference) {
		isValidState = false;
		if (!(fromCu instanceof Instruction) || !(editReference instanceof StackReference)) {
			throw new IllegalArgumentException("Valid instruction and stack reference required");
		}
		this.fromCodeUnit = fromCu;
		this.editRef = (StackReference) editReference;
		if (!editRef.isStackReference()) {
			throw new IllegalArgumentException("Valid stack reference required");
		}

		stackOffset.setText(toHexString(editRef.getStackOffset()));

		RefType rt = editRef.getReferenceType();
		populateRefTypes(rt);
		refTypes.setSelectedItem(rt);

		isValidState = true;
	}

	@Override
	public boolean initialize(CodeUnit fromCu, int fromOpIndex, int fromSubIndex) {
		isValidState = false;
		this.editRef = null;
		this.fromCodeUnit = fromCu;

		return setOpIndex(fromOpIndex);
	}

	@Override
	public boolean setOpIndex(int opIndex) {

		if (editRef != null) {
			throw new IllegalStateException("setOpIndex only permitted for ADD case");
		}

		isValidState = false;
		this.opIndex = opIndex;

		if (opIndex == EditReferencesProvider.MNEMONIC_OPINDEX ||
			!(fromCodeUnit instanceof Instruction)) {
			return false;
		}

		Function f = fromCodeUnit.getProgram().getFunctionManager().getFunctionContaining(
			fromCodeUnit.getMinAddress());
		if (f == null) {
			return false;
		}

		RefType rt = RefTypeFactory.getDefaultStackRefType(fromCodeUnit, opIndex);
		CallDepthChangeInfo depth = new CallDepthChangeInfo(f);
		int offset = depth.getStackOffset((Instruction) fromCodeUnit, opIndex);
		isValidStackRef = (offset != Function.INVALID_STACK_DEPTH_CHANGE);
		if (!isValidStackRef) {
			Scalar s = null;
			Object[] opObjs = ((Instruction) fromCodeUnit).getOpObjects(opIndex);
			for (Object obj : opObjs) {
				if (obj instanceof Scalar) {
					if (s != null) {
						s = null;
						break;
					}
					s = (Scalar) obj;
				}
			}
			offset = s != null ? (int) s.getValue() : 0;
		}
		stackOffset.setText(toHexString(offset));

		populateRefTypes(rt);
		refTypes.setSelectedItem(rt);

		isValidState = true;
		return true;
	}

	private String toHexString(long val) {
		boolean neg = (val < 0);
		return (neg ? "-" : "+") + "0x" + Long.toHexString(neg ? -val : val);
	}

	@Override
	public boolean applyReference() {
		if (!isValidState) {
			throw new IllegalStateException();
		}

		Program program = fromCodeUnit.getProgram();
		Function f =
			program.getFunctionManager().getFunctionContaining(fromCodeUnit.getMinAddress());
		if (f == null) {
			// Function no longer exists
			showInputErr("Stack reference not permitted!\nAddress " + fromCodeUnit.getMinAddress() +
				" is no longer contained within a function.");
			return false;
		}

		String str = stackOffset.getText();
		long offset;
		try {
			offset = parseLongInput(str);
		}
		catch (NumberFormatException e) {
			showInputErr("Valid 'Stack Offset' is required.");
			return false;
		}

		AddressSpace stackSpace = program.getAddressFactory().getStackSpace();
		long minOffset = stackSpace.getMinAddress().getOffset();
		long maxOffset = stackSpace.getMaxAddress().getOffset();
		if (offset < minOffset || offset > maxOffset) {
			showInputErr("'Stack Offset' value too " + (offset > 0 ? "large" : "small") +
				"\nMust be between " + toHexString(minOffset) + " and " + toHexString(maxOffset));
			return false;
		}

		RefType refType = (RefType) refTypes.getSelectedItem();
		if (refType == null) {
			showInputErr("A 'Ref-Type' must be selected.");
			return false;
		}

		if (editRef != null) {
			return plugin.updateReference(editRef, fromCodeUnit, (int) offset, refType);
		}
		return plugin.addReference(fromCodeUnit, opIndex, (int) offset, refType);

	}

	@Override
	public void cleanup() {
		isValidState = false;
		fromCodeUnit = null;
		editRef = null;
	}

	@Override
	public boolean isValidContext() {
		return isValidState;
	}

}
