package ghidra.pyhidra.interpreter;

import java.awt.event.KeyEvent;
import javax.swing.ImageIcon;

import ghidra.pyhidra.PyhidraPlugin;
import ghidra.util.HelpLocation;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.ToolBarData;
import resources.ResourceManager;

import static docking.DockingUtils.CONTROL_KEY_MODIFIER_MASK;

final class ResetAction extends DockingAction {

	private final PyhidraConsole console;

	ResetAction(PyhidraConsole console) {
		super("Reset", PyhidraPlugin.class.getSimpleName());
		this.console = console;
		setDescription("Reset the interpreter");
		ImageIcon image = ResourceManager.loadImage("images/reload3.png");
		setToolBarData(new ToolBarData(image));
		setEnabled(true);
		KeyBindingData key = new KeyBindingData(KeyEvent.VK_D, CONTROL_KEY_MODIFIER_MASK);
		setKeyBindingData(key);
		setHelpLocation(new HelpLocation(PyhidraPlugin.TITLE, "Reset_Interpreter"));
	}

	@Override
	public void actionPerformed(ActionContext context) {
		console.restart();
	}
}
