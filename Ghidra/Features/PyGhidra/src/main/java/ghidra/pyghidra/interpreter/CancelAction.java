package ghidra.pyghidra.interpreter;

import java.awt.event.KeyEvent;
import javax.swing.ImageIcon;

import docking.ActionContext;
import docking.action.KeyBindingData;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.pyghidra.PyGhidraPlugin;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;

final class CancelAction extends DockingAction {

	private final PyGhidraConsole console;

	CancelAction(PyGhidraConsole console) {
		super("Cancel", PyGhidraPlugin.class.getSimpleName());
		this.console = console;
		setDescription("Interrupt the interpreter");
		ImageIcon image = ResourceManager.loadImage("images/dialog-cancel.png");
		setToolBarData(new ToolBarData(image));
		setEnabled(true);
		KeyBindingData key = new KeyBindingData(KeyEvent.VK_I, CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingData(key);
		setHelpLocation(new HelpLocation(PyGhidraPlugin.TITLE, "Interrupt_Interpreter"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		console.interrupt();
	}
}
