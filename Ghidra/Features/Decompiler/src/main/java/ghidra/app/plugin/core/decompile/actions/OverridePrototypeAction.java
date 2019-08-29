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
package ghidra.app.plugin.core.decompile.actions;

import java.util.Iterator;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerController;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.function.EditFunctionSignatureDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;

public class OverridePrototypeAction extends DockingAction {
	private final DecompilerController controller;
	private final PluginTool tool;

	public class ProtoOverrideDialog extends EditFunctionSignatureDialog {
		private FunctionDefinition functionDefinition;

		public FunctionDefinition getFunctionDefinition() {
			return functionDefinition;
		}

		public ProtoOverrideDialog(PluginTool tool, Function func, String signature, String conv) {
			super(tool, "Override Signature", func);
			setSignature(signature);
			setCallingConvention(conv);
		}

		/**
		 * This method gets called when the user clicks on the OK Button.  The base
		 * class calls this method.
		 */
		@Override
		protected void okCallback() {
			// only close the dialog if the user made valid changes
			if (parseFunctionDefinition())
				close();
		}

		private boolean parseFunctionDefinition() {

			functionDefinition = null;

			try {
				functionDefinition = parseSignature();
			}
			catch (CancelledException e) {
				// ignore
			}

			if (functionDefinition == null) {
				return false;
			}

			GenericCallingConvention convention =
				GenericCallingConvention.guessFromName(getCallingConvention());
			functionDefinition.setGenericCallingConvention(convention);
			return true;
		}
	}

	public OverridePrototypeAction(String owner, PluginTool tool, DecompilerController controller) {
		super("Override Signature", owner);
		this.tool = tool;
		this.controller = controller;
		setPopupMenuData(new MenuData(new String[] { "Override Signature" }, "Decompile"));
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		if (!(context instanceof DecompilerActionContext)) {
			return false;
		}

		Function function = controller.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			// Let this through here and handle it in actionPerformed().  This lets us alert 
			// the user that they have to wait until the decompile is finished.  If we are not
			// enabled at this point, then the keybinding will be propagated to the global 
			// actions, which is not what we want.
			return true;
		}

		return getCallOp(controller) != null;
	}

	@Override
	public void actionPerformed(ActionContext context) {
		// Note: we intentionally do this check here and not in isEnabledForContext() so 
		// that global events do not get triggered.
		DecompilerActionContext decompilerActionContext = (DecompilerActionContext) context;
		if (decompilerActionContext.isDecompiling()) {
			Msg.showInfo(getClass(), context.getComponentProvider().getComponent(),
				"Decompiler Action Blocked",
				"You cannot perform Decompiler actions while the Decompiler is busy");
			return;
		}

		Function func = controller.getFunction();
		Program program = func.getProgram();
		PcodeOp op = getCallOp(controller);
		Function calledfunc = getCalledFunction(op);
		boolean varargs = false;
		if (calledfunc != null)
			varargs = calledfunc.hasVarArgs();
		if ((op.getOpcode() == PcodeOp.CALL) && !varargs) {
			if (OptionDialog.showOptionDialog(controller.getDecompilerPanel(),
				"Warning : Localized Override",
				"Incorrect information entered here may hide other good information.\n" +
					"For direct calls, it is usually better to alter the prototype on the function\n" +
					"itself, rather than overriding the local call. Proceed anyway?",
				"Proceed") != 1)
				return;
		}
		Address addr = op.getSeqnum().getTarget();
		String name = "func"; // Default if we don't have a real name
		String conv = program.getCompilerSpec().getDefaultCallingConvention().getName();
		if (calledfunc != null) {
			name = calledfunc.getName();
			conv = calledfunc.getCallingConventionName();
		}

		String signature = generateSignature(op, name);
		ProtoOverrideDialog dialog = new ProtoOverrideDialog(tool, func, signature, conv);
		//     dialog.setHelpLocation( new HelpLocation( getOwner(), "Edit_Function_Signature" ) );
		tool.showDialog(dialog);
		FunctionDefinition fdef = dialog.getFunctionDefinition();
		if (fdef == null)
			return;
		int transaction = program.startTransaction("Override Signature");
		boolean commit = false;
		try {
			HighFunctionDBUtil.writeOverride(func, addr, fdef);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(getClass(), controller.getDecompilerPanel(), "Override Signature Failed",
				"Error overriding signature: " + e);
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/**
	 * Try to find the PcodeOp representing the call the user has selected
	 * @return the PcodeOp or null
	 */
	public static PcodeOp getCallOp(DecompilerController controller) {
		DecompilerPanel decompilerPanel = controller.getDecompilerPanel();
		ClangToken tokenAtCursor = decompilerPanel.getTokenAtCursor();
		if (tokenAtCursor == null) {
			return null;
		}
		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return ((ClangFuncNameToken) tokenAtCursor).getPcodeOp();
		}

		Address addr = tokenAtCursor.getMinAddress();
		if (addr == null)
			return null;
		Instruction instr = controller.getProgram().getListing().getInstructionAt(addr);
		if (instr == null)
			return null;
		if (!instr.getFlowType().isCall())
			return null;
		ClangFunction cfunc = tokenAtCursor.getClangFunction();
		if (cfunc == null)
			return null;
		HighFunction hfunc = cfunc.getHighFunction();
		Iterator<PcodeOpAST> iter = hfunc.getPcodeOps(addr);
		while (iter.hasNext()) {
			PcodeOpAST op = iter.next();
			if ((op.getOpcode() == PcodeOp.CALL) || (op.getOpcode() == PcodeOp.CALLIND))
				return op;
		}

		return null;
	}

	private Function getCalledFunction(PcodeOp op) {
		if (op.getOpcode() != PcodeOp.CALL)
			return null;
		Address addr = op.getInput(0).getAddress();
		Program program = controller.getProgram();
		return program.getFunctionManager().getFunctionAt(addr);
	}

	private String generateSignature(PcodeOp op, String name) {
		StringBuffer buf = new StringBuffer();
		Varnode vn = op.getOutput();
		DataType dt = null;
		if (vn != null) {
			dt = vn.getHigh().getDataType();
		}
		if (dt != null)
			buf.append(dt.getDisplayName());
		else
			buf.append(DataType.VOID.getDisplayName());

		buf.append(' ').append(name).append('(');
		for (int i = 1; i < op.getNumInputs(); ++i) {
			vn = op.getInput(i);
			dt = null;
			if (vn != null)
				dt = vn.getHigh().getDataType();
			if (dt != null)
				buf.append(dt.getDisplayName());
			else
				buf.append("BAD");
			if (i != op.getNumInputs() - 1)
				buf.append(',');
		}
		buf.append(')');
		return buf.toString();
	}
}
