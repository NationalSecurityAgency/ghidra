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
package ghidra.app.core.debug.service.taint;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.util.List;

import db.Transaction;
import docking.ActionContext;
import docking.action.*;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.location.DefaultDecompilerLocation;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.breakpoint.DebuggerSleighSemanticInputDialog;
import ghidra.pcode.exec.SleighUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;

public class EmulatorTaintAction extends DockingAction {

	public static final String SET_TAINT_BY_ARR = """
			%s=taint_arr(%s);
			emu_exec_decoded();
			""";

	public static final String SET_TAINT_BY_VAR = """
			%s=taint_var(%s);
			emu_exec_decoded();
			""";

	private EmulationTaintInjectionServicePlugin plugin;
	private boolean byArray;
	private boolean verify = true;


	public EmulatorTaintAction(EmulationTaintInjectionServicePlugin plugin, boolean byArray) {
		super(byArray ? "TaintArr" : "TaintVar", plugin.getName());
		this.plugin = plugin;
		this.byArray = byArray;
		MenuData menuData =
			new MenuData(new String[] { "Toggle taint", byArray ? "by array" : "by var" },
				DebuggerResources.ICON_EMULATE, DebuggerResources.GROUP_GENERAL);
		setKeyBindingData(
			new KeyBindingData(KeyEvent.VK_T, byArray ? InputEvent.SHIFT_DOWN_MASK : 0));
		setPopupMenuData(menuData);
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return plugin.usingEmulator();
	}

	@Override
	public void actionPerformed(ActionContext context) {
		if (!(context instanceof ProgramLocationActionContext plctx)) {
			return;
		}
		Program currentProgram = plctx.getProgram();
		BookmarkManager bookmarkManager = currentProgram.getBookmarkManager();
		String sleigh = null;
		if (plugin.getTaint(plctx) == null) {
			sleigh = deriveCurrentSleighFromContext(plctx);
			if (sleigh == null) {
				sleigh = SleighUtils.UNCONDITIONAL_BREAK;
			}
			if (verify) {
				sleigh =
					DebuggerSleighSemanticInputDialog.INSTANCE.prompt(plugin.getTool(), sleigh);
				if (sleigh == null) {
					return;
				}
			}
			try (Transaction _ = currentProgram.openTransaction("set bookmark")) {
				bookmarkManager.setBookmark(plctx.getAddress(), BookmarkType.INFO, "Taint Source",
					sleigh);
			}
		}
		else {
			try (Transaction _ = currentProgram.openTransaction("clear bookmark")) {
				Bookmark bookmark = bookmarkManager.getBookmark(plctx.getAddress(),
					BookmarkType.INFO, "Taint Source");
				bookmarkManager.removeBookmark(bookmark);
			}
		}
		plugin.toggleTaint(plctx, sleigh);
	}

	private String deriveCurrentSleighFromContext(ProgramLocationActionContext plctx) {
		String sleigh = null;
		Program currentProgram = plctx.getProgram();
		ProgramLocation location = plctx.getLocation();
		Address address = location.getAddress();
		int row = location.getRow();
		int offset = location.getCharOffset();

		String cmds = byArray ? SET_TAINT_BY_ARR : SET_TAINT_BY_VAR;
		if (location instanceof PcodeFieldLocation pfl) {
			List<String> pcodeStrings = pfl.getPcodeStrings();
			String test = pcodeStrings.get(row);
			int lastSpace = test.lastIndexOf(" ");
			int index = offset > lastSpace ? 1 : 0;
			Instruction inst =
				currentProgram.getListing().getInstructionContaining(address);
			PcodeOp[] pcode = inst.getPcode();
			PcodeOp op = pcode[row];
			if (index >= op.getNumInputs()) {
				index--;
			}
			Varnode vn = op.getInput(index);
			String vnid = vn.toString(currentProgram.getLanguage());
			sleigh = cmds.formatted(vnid, vnid);
		}
		else if (location instanceof DefaultDecompilerLocation ddl) {
			ClangToken token = ddl.getToken();
			Varnode vn = token.getVarnode();
			String vnid = vn.toString(currentProgram.getLanguage());
			sleigh = cmds.formatted(vnid, vnid);
		}
		else if (location instanceof OperandFieldLocation ofl) {
			String opid = ofl.getOperandRepresentation();
			sleigh = cmds.formatted(opid, opid);
		}
		return sleigh;
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation(plugin.getName(), "set_injection");
	}
}
