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

import docking.widgets.dialogs.InputDialog;
import docking.widgets.dialogs.InputDialogListener;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * Class for renaming symbols within the decompiler window
 *
 */
public abstract class RenameTask {
	protected String newName = null;
	protected String oldName;
	protected String errorMsg = null;		// Error to return if isValid returns false
	protected PluginTool tool;
	protected Program program;
	protected DecompilerPanel decompilerPanel;
	protected ClangToken tokenAtCursor;
	
	public RenameTask(PluginTool tool, Program program, DecompilerPanel panel, ClangToken token,
			String old) {
		this.tool = tool;
		this.program = program;
		this.decompilerPanel = panel;
		this.tokenAtCursor = token;
		oldName = old;
	}
	
	public abstract String getTransactionName();
	
	public abstract boolean isValid(String newNm);
	
	public abstract void commit() throws DuplicateNameException, InvalidInputException;
	
	public String getNewName() { return newName; }
	
	/**
	 * Bring up a dialog that is initialized with the old name, and allows the user to select a new name
	 * @param oldNameIsCancel is true if the user keeping/entering the old name is considered a cancel
	 * @return true unless the user canceled
	 */
	private boolean runDialog(boolean oldNameIsCancel) {
		InputDialogListener listener = new InputDialogListener() {
			@Override
			public boolean inputIsValid(InputDialog dialog) {
				String name = dialog.getValue();
				if ((name==null)||(name.length()==0)) {
					dialog.setStatusText("Cannot have empty name");
					return false;
				}
				if (name.equals(oldName)) {		// No change to name
					newName = name;
					return true;				// but valid (ends up being equivalent to cancel
				}
				boolean res = isValid(name);
				if (!res) {
					dialog.setStatusText(errorMsg);
				}
				return res;
			}
		};
		
		String label = "Rename " + oldName + ":";
        InputDialog renameVarDialog = new InputDialog( getTransactionName(), 
                new String[]{ label }, new String[]{ oldName }, listener );
        
        tool.showDialog(renameVarDialog);
            
        if (renameVarDialog.isCanceled()) {
        	return false;
        }
		if (oldNameIsCancel && newName.equals(oldName)) {
			return false;
		}
        return true;		
		
	}

	/**
	 * Perform the task of selecting a new name and committing it to the database
	 * @param oldNameIsCancel is true if the user entering/keeping the old name is considered a cancel
	 */
	public void runTask(boolean oldNameIsCancel) {
		boolean dialogres = runDialog(oldNameIsCancel);
		if (dialogres) {
			int transaction = program.startTransaction(getTransactionName());
			boolean commit = false;
			try {
				commit();
				commit = true;
			}
			catch (DuplicateNameException e) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed", e.getMessage());
			}
			catch (InvalidInputException e) {
				Msg.showError(this, tool.getToolFrame(), "Rename Failed", e.getMessage());
			}
			finally {
				program.endTransaction(transaction, commit);
				decompilerPanel.tokenRenamed(tokenAtCursor, getNewName());
			}
		}

	}

	public static boolean isSymbolInFunction(Function function, String name) {
		SymbolTable symbolTable = function.getProgram().getSymbolTable();
		return !symbolTable.getSymbols(name, function).isEmpty();
	}
}
