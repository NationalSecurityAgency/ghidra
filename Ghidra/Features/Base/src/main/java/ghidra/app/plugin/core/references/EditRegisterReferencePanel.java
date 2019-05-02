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

import java.util.*;

import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;

import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.layout.PairLayout;

class EditRegisterReferencePanel extends EditReferencePanel {

	private static final RefType[] REGISTER_REF_TYPES = RefTypeFactory.getDataRefTypes();

	private ReferencesPlugin plugin;

	// Fields required for ADD
	private CodeUnit fromCodeUnit;
	private GhidraComboBox<Register> regList;
	private GhidraComboBox<RefType> refTypes;
	private int opIndex;

	// Fields required for EDIT
	private Reference editRef;

	private boolean isValidState;

	EditRegisterReferencePanel(ReferencesPlugin plugin) {
		super("REG");
		this.plugin = plugin;
		buildPanel();
	}

	private void buildPanel() {
		setLayout(new PairLayout(10, 10, 160));
		setBorder(new EmptyBorder(0, 5, 5, 5));

		regList = new GhidraComboBox<>();

		refTypes = new GhidraComboBox<>(REGISTER_REF_TYPES);

		add(new GLabel("Register:", SwingConstants.RIGHT));
		add(regList);
		add(new GLabel("Ref-Type:", SwingConstants.RIGHT));
		add(refTypes);
	}

	private void populateRefTypes(RefType adhocType) {
		refTypes.clearModel();
		for (int i = 0; i < REGISTER_REF_TYPES.length; i++) {
			if (adhocType == REGISTER_REF_TYPES[i]) {
				adhocType = null;
			}
			refTypes.addItem(REGISTER_REF_TYPES[i]);
		}
		if (adhocType != null) {
			refTypes.addItem(adhocType);
		}
	}

	private void populateRegisterList(Collection<Register> registers, Register selectedRegister) {
		regList.clearModel();
		for (Register reg : registers) {
			regList.addItem(reg);
		}
		if (selectedRegister != null) {
			regList.setSelectedItem(selectedRegister);
		}
	}

	private TreeSet<Register> getAllowedRegisters(Instruction instr, Register requiredReg) {
		Program program = instr.getProgram();
		Register stackPointer = program.getCompilerSpec().getStackPointer();
		TreeSet<Register> regSet = new TreeSet<>();
		for (Object obj : instr.getResultObjects()) {
			Register reg = null;
			if (obj instanceof Register) {
				reg = (Register) obj;
			}
			else if (obj instanceof Address) {
				reg = program.getRegister((Address) obj);
			}
			if (reg != null) {
				reg = reg.getBaseRegister();
				if (!reg.isHidden() && !reg.isProcessorContext() && !reg.isProgramCounter() &&
					(stackPointer == null || !stackPointer.equals(reg))) {
					regSet.add(reg);
					addChildRegisters(reg, regSet);
				}
			}
		}
		if (requiredReg != null && !regSet.contains(requiredReg)) {
			regSet.add(requiredReg);
		}
		return regSet;
	}

	private void addChildRegisters(Register reg, Set<Register> regSet) {
		for (Register child : reg.getChildRegisters()) {
			regSet.add(child);
			addChildRegisters(child, regSet);
		}
	}

	@Override
	public void initialize(CodeUnit fromCu, Reference editReference) {
		isValidState = false;
		if (!(fromCu instanceof Instruction)) {
			throw new IllegalArgumentException("Valid instruction required");
		}
		Register toReg = fromCu.getProgram().getRegister(editReference.getToAddress());
		if (toReg == null) {
			throw new IllegalArgumentException("Valid register reference required");
		}
		this.fromCodeUnit = fromCu;
		this.editRef = editReference;

		populateRegisterList(getAllowedRegisters((Instruction) fromCu, toReg), toReg);

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

	private static Register findOperandRegister(Instruction instr, int opIndex) {
		Object[] objs = instr.getOpObjects(opIndex);
		if (objs.length == 1) {
			if (objs[0] instanceof Register) {
				return (Register) objs[0];
			}
			if (objs[0] instanceof Address) {
				return instr.getProgram().getRegister((Address) objs[0]);
			}
		}
		return null;
	}

	@Override
	public boolean setOpIndex(int fromOpIndex) {

		if (editRef != null) {
			throw new IllegalStateException("setOpIndex only permitted for ADD case");
		}

		isValidState = false;
		this.opIndex = fromOpIndex;

		if (!(fromCodeUnit instanceof Instruction)) {
			return false;
		}

		Function f = fromCodeUnit.getProgram().getFunctionManager().getFunctionContaining(
			fromCodeUnit.getMinAddress());
		if (f == null) {
			return false;
		}

		Instruction instr = (Instruction) fromCodeUnit;
		TreeSet<Register> allowedRegisters = getAllowedRegisters(instr, null);
		if (allowedRegisters.isEmpty()) {
			return false;
		}
		Register preferredReg = findOperandRegister(instr, fromOpIndex);
		populateRegisterList(allowedRegisters, preferredReg);

		populateRefTypes(null);
		refTypes.setSelectedItem(RefType.WRITE);

		isValidState = true;
		return true;
	}

	@Override
	public boolean applyReference() {
		if (!isValidState) {
			throw new IllegalStateException();
		}

		Function f = fromCodeUnit.getProgram().getFunctionManager().getFunctionContaining(
			fromCodeUnit.getMinAddress());
		if (f == null) {
			// Function no longer exists
			showInputErr("Register reference not permitted!\nAddress " +
				fromCodeUnit.getMinAddress() + " is no longer contained within a function.");
			return false;
		}

		RefType refType = (RefType) refTypes.getSelectedItem();
		if (refType == null) {
			showInputErr("A 'Ref-Type' must be selected.");
			return false;
		}

		Register toReg = (Register) regList.getSelectedItem();
		if (toReg == null) {
			showInputErr("A 'Register' must be selected.");
			return false;
		}

		if (editRef != null) {
			return plugin.updateReference(editRef, fromCodeUnit, toReg, refType);
		}
		return plugin.addReference(fromCodeUnit, opIndex, toReg, refType);
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
