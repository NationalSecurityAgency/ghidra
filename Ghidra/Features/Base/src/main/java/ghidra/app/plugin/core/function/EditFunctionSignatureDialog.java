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
package ghidra.app.plugin.core.function;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.framework.cmd.Command;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

/**
 * <code>EditFunctionSignatureDialog</code> provides the ability to edit the
 * function signature associated with a specific {@link Function}.  
 * Use of this editor requires the presence of the tool-based datatype manager service.
 */
public class EditFunctionSignatureDialog extends AbstractEditFunctionSignatureDialog {

	protected final Function function;
	protected final String oldFunctionSignature;

	/**
	 * Edit function signature for a specified Function
	 * @param tool A reference to the active tool.
	 * @param title The title of the dialog.
	 * @param function the function which is having its signature edited.
	 */
	public EditFunctionSignatureDialog(PluginTool tool, String title, final Function function) {
		super(tool, title, allowInLine(function), true, allowCallFixup(function));
		this.function = function;
		this.oldFunctionSignature = function.getSignature().getPrototypeString();
	}

	protected EditFunctionSignatureDialog(PluginTool tool, String title, final Function function,
			boolean allowInLine, boolean allowNoReturn, boolean allowCallFixup) {
		super(tool, title, allowInLine, allowNoReturn, allowCallFixup);
		this.function = function;
		this.oldFunctionSignature = function.getSignature().getPrototypeString();
	}

	@Override
	protected FunctionSignature getFunctionSignature() {
		return function.getSignature();
	}

	@Override
	protected String getPrototypeString() {
		return oldFunctionSignature;
	}

	@Override
	protected String getCallingConventionName() {
		return function.getCallingConventionName();
	}

	@Override
	protected List<String> getCallingConventionNames() {
		List<String> list = new ArrayList<>();
		list.add(Function.UNKNOWN_CALLING_CONVENTION_STRING);
		list.add(Function.DEFAULT_CALLING_CONVENTION_STRING);
		list.addAll(function.getProgram().getFunctionManager().getCallingConventionNames());
		return list;
	}

	@Override
	protected boolean isInline() {
		return function.isInline();
	}

	@Override
	protected boolean hasNoReturn() {
		return function.hasNoReturn();
	}

	@Override
	protected String getCallFixupName() {
		return function.getCallFixup();
	}

	private static String[] getCallFixupNames(Function function) {
		String[] callFixupNames =
			function.getProgram().getCompilerSpec().getPcodeInjectLibrary().getCallFixupNames();
		if (callFixupNames.length == 0) {
			return null;
		}
		return callFixupNames;
	}

	@Override
	protected String[] getSupportedCallFixupNames() {
		return getCallFixupNames(function);
	}

	@Override
	protected DataTypeManager getDataTypeManager() {
		return function.getProgram().getDataTypeManager();
	}

	/**
	 * Get the effective function to which changes will be made.  This
	 * will be the same as function unless it is a thunk in which case
	 * the returned function will be the ultimate non-thunk function.
	 * @param f function
	 * @return non-thunk function
	 */
	private static Function getEffectiveFunction(Function f) {
		return f.isThunk() ? f.getThunkedFunction(true) : f;
	}

	private static boolean allowInLine(Function function) {
		return !getEffectiveFunction(function).isExternal();
	}

	private static boolean allowCallFixup(Function function) {
		return getCallFixupNames(function) != null;
	}

	/**
	 * Called when the user initiates changes that need to be put into a
	 * command and executed.
	 *
	 * @return true if the command was successfully created.
	 * @throws CancelledException if operation cancelled by user
	 */
	@Override
	protected boolean applyChanges() throws CancelledException {
		// create the command
		Command<Program> command = createCommand();

		if (command == null) {
			return false;
		}

		// run the command
		if (!getTool().execute(command, function.getProgram())) {
			setStatusText(command.getStatusMsg());
			return false;
		}

		setStatusText("");
		return true;
	}

	private Command<Program> createCommand() throws CancelledException {

		Command<Program> cmd = null;
		if (isSignatureChanged() || isCallingConventionChanged() ||
			(function.getSignatureSource() == SourceType.DEFAULT)) {

			FunctionDefinitionDataType definition = parseSignature();
			if (definition == null) {
				return null;
			}
			cmd = new ApplyFunctionSignatureCmd(function.getEntryPoint(), definition,
				SourceType.USER_DEFINED, true, false, DataTypeConflictHandler.DEFAULT_HANDLER,
				FunctionRenameOption.RENAME);
		}

		CompoundCmd<Program> compoundCommand = new CompoundCmd<>("Update Function Signature");

		compoundCommand.add(new Command<Program>() {
			String errMsg = null;

			@Override
			public boolean applyTo(Program p) {
				try {
					String conventionName = getCallingConvention();
					function.setCallingConvention(conventionName);
					return true;
				}
				catch (InvalidInputException e) {
					errMsg = e.getMessage();
					Msg.error(this, "Unexpected Exception: " + e.getMessage(), e);
					return false;
				}
			}

			@Override
			public String getName() {
				return "Update Function Calling Convention";
			}

			@Override
			public String getStatusMsg() {
				return errMsg;
			}
		});
		if (allowInLine) {
			compoundCommand.add(new Command<Program>() {
				@Override
				public boolean applyTo(Program p) {
					function.setInline(isInlineSelected());
					return true;
				}

				@Override
				public String getName() {
					return "Update Function Inline Flag";
				}

				@Override
				public String getStatusMsg() {
					return null;
				}
			});
		}
		if (allowNoReturn) {
			compoundCommand.add(new Command<Program>() {
				@Override
				public boolean applyTo(Program p) {
					function.setNoReturn(hasNoReturnSelected());
					return true;
				}

				@Override
				public String getName() {
					return "Update Function No Return Flag";
				}

				@Override
				public String getStatusMsg() {
					return null;
				}
			});
		}
		if (allowCallFixup) {
			compoundCommand.add(new Command<Program>() {
				@Override
				public boolean applyTo(Program p) {
					function.setCallFixup(getCallFixupSelection());
					return true;
				}

				@Override
				public String getName() {
					return "Update Function Call-Fixup";
				}

				@Override
				public String getStatusMsg() {
					return null;
				}
			});
		}
		if (cmd != null) {
			compoundCommand.add(cmd);
		}
		return compoundCommand;
	}

}
