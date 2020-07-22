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

import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.decompiler.*;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.function.EditFunctionSignatureDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;
import ghidra.util.UndefinedFunction;
import ghidra.util.exception.CancelledException;

public class OverridePrototypeAction extends AbstractDecompilerAction {

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
			if (parseFunctionDefinition()) {
				close();
			}
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

	public OverridePrototypeAction() {
		super("Override Signature");
		setPopupMenuData(new MenuData(new String[] { "Override Signature" }, "Decompile"));
	}

	/**
	 * Try to find the PcodeOp representing the call the user has selected
	 * @param program is the Program
	 * @param tokenAtCursor is the point in the window the user has selected
	 * @return the PcodeOp or null
	 */
	private static PcodeOp getCallOp(Program program, ClangToken tokenAtCursor) {
		if (tokenAtCursor == null) {
			return null;
		}

		if (tokenAtCursor instanceof ClangFuncNameToken) {
			return ((ClangFuncNameToken) tokenAtCursor).getPcodeOp();
		}

		Address addr = tokenAtCursor.getMinAddress();
		if (addr != null) {
			PcodeOp op = getOpForAddress(program, addr, tokenAtCursor);
			if (op != null) {
				return op;
			}
		}

		ClangNode parent = tokenAtCursor.Parent();
		if (parent instanceof ClangStatement) {
			PcodeOp op = ((ClangStatement) parent).getPcodeOp();
			int opCode = op.getOpcode();
			if (opCode == PcodeOp.CALL || opCode == PcodeOp.CALLIND) {
				return op;
			}
		}

		return null;
	}

	private static PcodeOp getOpForAddress(Program program, Address addr, ClangToken token) {

		ClangFunction cfunc = token.getClangFunction();
		if (cfunc == null) {
			return null;
		}

		Instruction instr = program.getListing().getInstructionAt(addr);
		if (instr == null) {
			return null;
		}

		if (!instr.getFlowType().isCall()) {
			return null;
		}

		HighFunction hfunc = cfunc.getHighFunction();
		Iterator<PcodeOpAST> iter = hfunc.getPcodeOps(addr);
		while (iter.hasNext()) {
			PcodeOpAST op = iter.next();
			int opCode = op.getOpcode();
			if (opCode == PcodeOp.CALL || opCode == PcodeOp.CALLIND) {
				return op;
			}
		}

		return null;
	}

	private Function getCalledFunction(Program program, PcodeOp op) {
		if (op.getOpcode() != PcodeOp.CALL) {
			return null;
		}
		Address addr = op.getInput(0).getAddress();
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionAt(addr);
		if (function != null) {
			return function;
		}
		Address opAddr = op.getSeqnum().getTarget();
		Reference[] references = program.getReferenceManager().getFlowReferencesFrom(opAddr);
		for (Reference ref : references) {
			if (ref.getReferenceType().isCall()) {
				function = functionManager.getFunctionAt(ref.getToAddress());
				if (function != null) {
					return function;
				}
			}
		}
		return null;
	}

	private String generateSignature(PcodeOp op, String name) {
		StringBuffer buf = new StringBuffer();
		Varnode vn = op.getOutput();
		DataType dt = null;
		if (vn != null) {
			dt = vn.getHigh().getDataType();
		}
		if (dt != null) {
			buf.append(dt.getDisplayName());
		}
		else {
			buf.append(DataType.VOID.getDisplayName());
		}

		buf.append(' ').append(name).append('(');
		for (int i = 1; i < op.getNumInputs(); ++i) {
			vn = op.getInput(i);
			dt = null;
			if (vn != null) {
				dt = vn.getHigh().getDataType();
			}
			if (dt != null) {
				buf.append(dt.getDisplayName());
			}
			else {
				buf.append("BAD");
			}
			if (i != op.getNumInputs() - 1) {
				buf.append(',');
			}
		}
		buf.append(')');
		return buf.toString();
	}

	@Override
	protected boolean isEnabledForDecompilerContext(DecompilerActionContext context) {
		Function function = context.getFunction();
		if (function == null || function instanceof UndefinedFunction) {
			return false;
		}

		PcodeOp callOp = getCallOp(context.getProgram(), context.getTokenAtCursor());
		return callOp != null;
	}

	@Override
	protected void decompilerActionPerformed(DecompilerActionContext context) {
		Function func = context.getFunction();
		Program program = func.getProgram();
		PcodeOp op = getCallOp(program, context.getTokenAtCursor());
		Function calledfunc = getCalledFunction(program, op);
		boolean varargs = false;
		if (calledfunc != null) {
			varargs = calledfunc.hasVarArgs();
		}
		if ((op.getOpcode() == PcodeOp.CALL) && !varargs) {
			if (OptionDialog.showOptionDialog(context.getDecompilerPanel(),
				"Warning : Localized Override",
				"Incorrect information entered here may hide other good information.\n" +
					"For direct calls, it is usually better to alter the prototype on the function\n" +
					"itself, rather than overriding the local call. Proceed anyway?",
				"Proceed") != 1) {
				return;
			}
		}
		Address addr = op.getSeqnum().getTarget();
		String name = "func"; // Default if we don't have a real name
		String conv = program.getCompilerSpec().getDefaultCallingConvention().getName();
		if (calledfunc != null) {
			name = calledfunc.getName();
			conv = calledfunc.getCallingConventionName();
		}

		String signature = generateSignature(op, name);
		PluginTool tool = context.getTool();
		ProtoOverrideDialog dialog = new ProtoOverrideDialog(tool, func, signature, conv);
		//     dialog.setHelpLocation( new HelpLocation( getOwner(), "Edit_Function_Signature" ) );
		tool.showDialog(dialog);
		FunctionDefinition fdef = dialog.getFunctionDefinition();
		if (fdef == null) {
			return;
		}
		int transaction = program.startTransaction("Override Signature");
		boolean commit = false;
		try {
			HighFunctionDBUtil.writeOverride(func, addr, fdef);
			commit = true;
		}
		catch (Exception e) {
			Msg.showError(getClass(), context.getDecompilerPanel(), "Override Signature Failed",
				"Error overriding signature: " + e);
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}
}
