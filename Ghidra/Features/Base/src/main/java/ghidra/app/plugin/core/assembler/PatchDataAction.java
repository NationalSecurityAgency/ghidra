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
package ghidra.app.plugin.core.assembler;

import java.awt.Font;
import java.awt.event.FocusListener;
import java.awt.event.KeyListener;

import javax.swing.*;

import db.Transaction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.FieldLocation;
import generic.theme.GThemeDefaults.Colors;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeEncodeException;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * A context menu action to patch data at the current address
 */
public class PatchDataAction extends AbstractPatchAction {
	private static final KeyStroke KEYBIND_PATCH_DATA = KeyStroke.getKeyStroke("ctrl shift H");

	/*test*/ final JTextField input = new JTextField();

	public PatchDataAction(Plugin owner) {
		this(owner, "Patch Data");
	}

	public PatchDataAction(Plugin owner, String name) {
		super(owner, name);

		setPopupMenuData(new MenuData(new String[] { name }, MENU_GROUP));
		setKeyBindingData(new KeyBindingData(KEYBIND_PATCH_DATA));
		setHelpLocation(new HelpLocation(owner.getName(), "patch_data"));

		input.setBorder(BorderFactory.createLineBorder(Colors.ERROR, 2));

		init();
	}

	@Override
	protected void addInputFocusListener(FocusListener listener) {
		input.addFocusListener(listener);
	}

	@Override
	protected void addInputKeyListener(KeyListener listener) {
		input.addKeyListener(listener);
	}

	@Override
	protected boolean isApplicableToUnit(CodeUnit cu) {
		if (!(cu instanceof Data)) {
			return false;
		}
		Data data = (Data) cu;
		if (!data.getBaseDataType().isEncodable()) {
			return false;
		}
		return true;
	}

	protected Data getData() {
		return (Data) getCodeUnit();
	}

	@Override
	protected void setInputFont(Font font) {
		input.setFont(font);
	}

	@Override
	protected boolean showInputs(FieldPanel fieldPanel) {
		FieldLocation locOpns = findFieldLocation(getAddress(), "Operands");
		if (locOpns == null) {
			Msg.showError(this, fieldPanel, getName(),
				"The Operands field must be present to patch data");
			return false;
		}
		fieldPanel.add(input, locOpns);
		input.setVisible(true);
		input.grabFocus();
		return true;
	}

	@Override
	protected void fillInputs() {
		String repr = getData().getDefaultValueRepresentation();
		input.setText(repr);
		input.setCaretPosition(repr.length());
	}

	@Override
	public void accept() {
		Program program = getProgram();
		Address address = getAddress();
		Data data = getData();
		DataType dt = data.getBaseDataType();
		/**
		 * Do as much outside the transaction as possible. The tool tends to steal focus away upon
		 * restoring the database, and that causes the input fields to disappear.
		 */
		byte[] encoded;
		AddressRange rng;
		try {
			encoded = dt.encodeRepresentation(input.getText(), data, data, data.getLength());
			rng = new AddressRangeImpl(address, encoded.length);
		}
		catch (DataTypeEncodeException | AddressOverflowException e) {
			tool.setStatusInfo(e.getMessage(), true);
			return;
		}
		try (Transaction tx =
			program.openTransaction("Patch Data @" + address + ": " + input.getText())) {
			int oldLength = data.getLength();
			if (encoded.length != oldLength) {
				program.getListing().clearCodeUnits(address, rng.getMaxAddress(), false);
			}
			program.getMemory().setBytes(address, encoded);
			if (encoded.length != oldLength) {
				program.getListing().createData(address, dt, encoded.length);
			}
			hide();
		}
		catch (MemoryAccessException e) {
			Msg.showError(this, null, "Patch Failure", e.getMessage(), e);
		}
		catch (CodeUnitInsertionException e) {
			throw new AssertionError(); // Should have been cleared first
		}
	}
}
