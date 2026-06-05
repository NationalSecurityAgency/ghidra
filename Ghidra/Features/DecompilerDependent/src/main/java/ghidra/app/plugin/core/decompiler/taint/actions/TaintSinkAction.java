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
package ghidra.app.plugin.core.decompiler.taint.actions;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompiler.taint.TaintPlugin;
import ghidra.app.plugin.core.decompiler.taint.TaintState.MarkType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.HelpLocation;
import ghidra.util.UndefinedFunction;

/**
 * Action triggered from a specific token in the decompiler window to mark a variable as a
 * source or sink and generate the requisite query. This can be an input parameter,
 * a stack variable, a variable associated with a register, or a "dynamic" variable. 
 */
public class TaintSinkAction extends TaintAbstractDecompilerAction {

	private TaintPlugin plugin;
	private MarkType mtype;

	public TaintSinkAction(TaintPlugin plugin) {
		super("Mark Sink");
		setHelpLocation(new HelpLocation(TaintPlugin.HELP_LOCATION, "TaintSink"));
		setPopupMenuData(new MenuData(new String[] { "Taint", "Sink" }, "Decompile"));
		setKeyBindingData(new KeyBindingData(KeyEvent.VK_S, InputEvent.SHIFT_DOWN_MASK));
		this.plugin = plugin;
		this.mtype = MarkType.SINK;
	}

	protected void mark(ClangToken token) {
		plugin.toggleIcon(mtype, token, false);
	}

	/**
	 * Designate an item in the decompiler window as a sink. This can only be done if you are
	 * on a HighSymbol
	 */
	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		if (plugin.getTaintState() == null) {
			return false;
		}

		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFieldToken) {
			return true;
		}
		if (tokenAtCursor.Parent() instanceof ClangReturnType) {
			return false;
		}
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return true;
		}
		if (tokenAtCursor instanceof ClangOpToken) {
			return true;
		}
		if (!tokenAtCursor.isVariableRef()) {
			return false;
		}
		return true;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		ClangToken tokenAtCursor = context.getTokenAtCursor();
		if (tokenAtCursor instanceof ClangOpToken) {
			markOp(tokenAtCursor);
		}
		else {
			mark(tokenAtCursor);
		}
	}

	private void markOp(ClangToken tokenAtCursor) {
		ClangLine line = tokenAtCursor.getLineParent();
		for (ClangToken token : line.getAllTokens()) {
			if (token instanceof ClangVariableToken varToken) {
				if (varToken.isVariableRef()) {
					Varnode varnode = varToken.getVarnode();
					if (varnode != null && !varnode.isConstant()) {
						mark(varToken);
					}
				}
			}
		}
	}
}
