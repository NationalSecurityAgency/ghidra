package ghidra.app.plugin.core.pcodepatch;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.UnknownInstructionException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

public class PatchPcodeTextDialog extends DialogComponentProvider {

    private GhidraComboBox<String> patchingTextComboBox;
    private PcodePatchPlugin plugin;

	private JLabel label;

    private AbstractPcodePatchAction action;
    private Pattern hexNumPattern = Pattern.compile(".*[abcdefABCDEF].*");


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

    private long parseLong(String longString) {
        if (longString.startsWith("0x")) {
            return Long.parseLong(longString.substring(2), 16);
        } else if (hexNumPattern.matcher(longString).matches()) {
            return Long.parseLong(longString, 16);
        } else {
            return Long.parseLong(longString);
        }
    }

    private int parseInt(String intString) {
        if (intString.startsWith("0x")) {
            return Integer.parseInt(intString.substring(2), 16);
        } else if (hexNumPattern.matcher(intString).matches()) {
            return Integer.parseInt(intString, 16);
        } else {
            return Integer.parseInt(intString);
        }
    }

    private Varnode parseVarnode(String varnodeText) throws Exception {
        // form: (space, offset, size)
            String[] parts = Stream.of(
                varnodeText
                .trim()
                .replace("(", "")
                .replace(")", "")
                .split(","))
                .map(part -> part.trim())
                .toArray(String[]::new);
            String space = parts[0];

            long offset = parseLong(parts[1]);
            int size = parseInt(parts[2]);

            if (space.equals("null")) {
                return null;
            }

            AddressFactory addressFactory = this.plugin.getCurrentProgram().getAddressFactory();

            AddressSpace addrSpace = addressFactory.getAddressSpace(space);
            if (addrSpace == null) {
                String msg = String.format("Invalid address space name %s", space);
                throw new Exception(msg);
            }

            Address addr = addressFactory.getAddress(addrSpace.getSpaceID(), offset);
            return new Varnode(addr, size);
    }

    private void parsePcodeOpThenDoPatch(String pcodeText) {
        // form: varnode_out = OP varnode_in1 varnode_in2 ...
        try {
            String[] parts = Stream.of(pcodeText.split("=")).map(x -> x.trim()).toArray(String[]::new);
            Varnode varnodeOut = parseVarnode(parts[0]);

            if (varnodeOut == null) {
                return;
            }

            String[] rhs_parts = parts[1].trim().split(" ");
            int pcodeOpCode = PcodeOp.getOpcode(rhs_parts[0]);
            rhs_parts = Arrays.copyOfRange(rhs_parts, 1, rhs_parts.length);

            String inVarnodeText = String.join("", rhs_parts)
                .replace(")", ") "); // spaces only between varnodes

            ArrayList<Varnode> varnodeIns = new ArrayList<>();

            for (var varnodeText : inVarnodeText.split(" ")) {
                varnodeIns.add(parseVarnode(varnodeText));
            }

            action.doPatch(pcodeOpCode, varnodeIns.toArray(Varnode[]::new), varnodeOut);
            close();
        } catch (UnknownInstructionException e) {
            Msg.showError(this, null, "Pcode Error", "pcode opcode unknown");
        } catch (Exception e) {
            Msg.showError(this, null, "Pcode Error", "Invalid pcode expression: " + e.toString());
        }
    }

    @Override
    protected void okCallback() {
        String text = patchingTextComboBox.getText();

        parsePcodeOpThenDoPatch(text);
    }
}
