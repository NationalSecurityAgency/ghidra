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
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeData;
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

    private void parsePcodeOpThenDoPatch(String pcodeText) {
        // form: varnode_out = OP varnode_in1 varnode_in2 ...
        try {
            AddressFactory addressFactory = this.plugin.getCurrentProgram().getAddressFactory();

            PcodeData patchPcode = PcodeRawParser.parseSingleRawPcode(addressFactory, pcodeText);
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
