/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
import ghidra.framework.plugintool.PluginTool;
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
	
	public RenameTask(PluginTool tool,String old) {
		this.tool = tool;
		oldName = old;
	}
	
	public abstract String getTransactionName();
	
	public abstract boolean isValid(String newNm);
	
	public abstract void commit() throws DuplicateNameException, InvalidInputException;
	
	public String getNewName() { return newName; }
	
	/**
	 * Bring up a dialog that is initialized with the old name, and allows the user to select a new name
	 * @return true unless the user canceled
	 */
	public boolean runDialog() {
		InputDialogListener listener = new InputDialogListener() {
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
				if (!res)
					dialog.setStatusText(errorMsg);
				return res;
			}
		};
		
		String label = "Rename " + oldName + ":";
        InputDialog renameVarDialog = new InputDialog( getTransactionName(), 
                new String[]{ label }, new String[]{ oldName }, true, listener );
        
        tool.showDialog(renameVarDialog);
            
        if (renameVarDialog.isCanceled()) {
        	return false;
        }
        if (newName.equals(oldName))		// No change to name
        	return false;
        return true;		
		
	}
	
}
