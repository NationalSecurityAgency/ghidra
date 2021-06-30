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

package ghidra.app.plugin.core.pcodepatch;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.RawPcodeImpl;
import ghidra.program.model.pcode.PcodeRawParser;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.TaskMonitor;

public class PatchPcodeTextDialog extends DialogComponentProvider {

    private GhidraComboBox<String> patchingTextComboBox;
    private PcodePatchPlugin plugin;

	private JLabel label;

    private AbstractPcodePatchAction action;

    public PatchPcodeTextDialog(PcodePatchPlugin plugin, AbstractPcodePatchAction action) {
        super("Patch Pcode", false, false, true, false);

        this.plugin = plugin;
        this.action = action;

        addWorkPanel(buildMainPanel());
        addOKButton();
        addCancelButton();
    }

    protected JPanel buildMainPanel() {
		JPanel mainPanel = new JPanel(new PairLayout(5, 5));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

		label = new GDLabel("Pcode: ");

        patchingTextComboBox = new GhidraComboBox<>();
        patchingTextComboBox.setEditable(true);
		patchingTextComboBox.addActionListener(ev -> okCallback());

        JTextField patchingTextField = (JTextField) patchingTextComboBox.getEditor().getEditorComponent();
        patchingTextField.setColumns(20);

		mainPanel.add(label);
		mainPanel.add(patchingTextComboBox);

		return mainPanel;
	}

    public void show() {
        this.plugin.getTool().showDialog(this);
    }

    /**
     * show the dialog with initial text set with the raw Pcode at pointed instruction
     * 
     * @param initialText the initial text displayed in the patching dialog
     */
    public void show(String initialText) {
        JTextField patchingTextField = (JTextField) patchingTextComboBox.getEditor().getEditorComponent();
        patchingTextField.setText(initialText);
        show();
    }

    private void parsePcodeOpThenDoPatch(String pcodeText) {
        try {
            AddressFactory addressFactory = this.plugin.getCurrentProgram().getAddressFactory();

            RawPcodeImpl patchPcode = PcodeRawParser.parseSingleRawPcode(addressFactory, pcodeText);
            Program program = this.plugin.getCurrentProgram();

            this.plugin.getTool().execute(new BackgroundCommand() {

                @Override
                public boolean applyTo(DomainObject obj, TaskMonitor monitor) {
                    try {
                        action.doPatch(patchPcode);
                        return true;
                    } catch (Exception e) {
                        Msg.showError(this, null, "Can't Patch Pcode", e.toString());
                        return false;
                    }
                }

                @Override
                public String getStatusMsg() {
                    return null;
                }

                @Override
                public String getName() {
                    return "PcodePatch";
                }

            }, program);
            close();
        } catch (RuntimeException e) {
            Msg.showError(this, null, "Pcode Error", "pcode opcode unknown: " + e.toString());
        }
    }

    @Override
    protected void okCallback() {
        String text = patchingTextComboBox.getText();

        parsePcodeOpThenDoPatch(text);
    }
}
