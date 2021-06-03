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
import ghidra.app.util.HelpTopics;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;

public class OverridePrototypeAction extends AbstractDecompilerAction {

	public OverridePrototypeAction() {
		super("Override Signature");
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionOverrideSignature"));
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
			if (isCallOp(op)) {
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
			if (isCallOp(op)) {
				return op;
			}
		}

		return null;
	}

	private static boolean isCallOp(PcodeOp op) {

		if (op == null) {
			return false;
		}

		int opCode = op.getOpcode();
		return opCode == PcodeOp.CALL || opCode == PcodeOp.CALLIND;
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

	private String generateSignature(PcodeOp op, String name, Function calledfunc) {

		// TODO: If an override has already be placed-down it should probably be used 
		// for the initial signature.  HighFunction does not make it easy to grab 
		// existing override prototype

		if (calledfunc != null) {
			SourceType signatureSource = calledfunc.getSignatureSource();
			if (signatureSource == SourceType.DEFAULT || signatureSource == SourceType.ANALYSIS) {
				calledfunc = null; // ignore
			}
		}

		StringBuffer buf = new StringBuffer();

		Varnode vn = op.getOutput();
		DataType dt = null;
		if (calledfunc != null) {
			dt = calledfunc.getReturnType();
			if (Undefined.isUndefined(dt)) {
				dt = null;
			}
		}
		if (dt == null && vn != null) {
			dt = vn.getHigh().getDataType();
		}
		if (dt != null) {
			buf.append(dt.getDisplayName());
		}
		else {
			buf.append(DataType.VOID.getDisplayName());
		}

		buf.append(' ').append(name).append('(');

		int index = 1;
		if (calledfunc != null) {
			for (Parameter p : calledfunc.getParameters()) {
				String dtName = getInputDataTypeName(op, index, p.getDataType());
				if (index++ != 1) {
					buf.append(", ");
				}
				buf.append(dtName);
				if (p.getSource() != SourceType.DEFAULT) {
					buf.append(' ');
					buf.append(p.getName());
				}
			}
		}

		for (int i = index; i < op.getNumInputs(); ++i) {
			if (i != 1) {
				buf.append(", ");
			}
			buf.append(getInputDataTypeName(op, i, null));
		}

		buf.append(')');
		return buf.toString();
	}

	private String getInputDataTypeName(PcodeOp op, int inIndex, DataType preferredDt) {
		if (preferredDt != null && !Undefined.isUndefined(preferredDt)) {
			return preferredDt.getDisplayName();
		}
		Varnode vn = op.getInput(inIndex);
		DataType dt = null;
		if (vn != null) {
			dt = vn.getHigh().getDataType();
		}
		if (dt != null) {
			return dt.getDisplayName();
		}
		return "BAD";
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

		String signature = generateSignature(op, name, calledfunc);
		PluginTool tool = context.getTool();
		ProtoOverrideDialog dialog =
			new ProtoOverrideDialog(tool, calledfunc != null ? calledfunc : func, signature, conv);
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

	/**
	 * <code>ProtoOverrideDialog</code> provides the ability to edit the
	 * function signature associated with a specific function definition override
	 * at a sub-function callsite.  
	 * Use of this editor requires the presence of the tool-based datatype manager service.
	 */
	private class ProtoOverrideDialog extends EditFunctionSignatureDialog {
		private FunctionDefinition functionDefinition;
		private final String initialSignature;
		private final String initialConvention;

		/**
		 * Construct signature override for called function
		 * @param tool active tool
		 * @param func function from which program access is achieved and supply of preferred 
		 * datatypes when parsing signature
		 * @param signature initial prototype signature to be used
		 * @param conv initial calling convention
		 */
		public ProtoOverrideDialog(PluginTool tool, Function func, String signature, String conv) {
			super(tool, "Override Signature", func, false, false, false);
			setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionOverrideSignature"));
			this.initialSignature = signature;
			this.initialConvention = conv;
		}

		@Override
		protected String getPrototypeString() {
			return initialSignature;
		}

		@Override
		protected String getCallingConventionName() {
			return initialConvention;
		}

		@Override
		protected boolean applyChanges() throws CancelledException {
			return parseFunctionDefinition();
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

		public FunctionDefinition getFunctionDefinition() {
			return functionDefinition;
		}
	}
}
