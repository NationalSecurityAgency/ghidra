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
package ghidra.app.plugin.core.function;

import ghidra.app.cmd.function.SetVariableCommentCmd;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;

/**
 * Dialog for setting the comments for a CodeUnit.
 */
class VariableCommentDialog extends CommentDialog {
	private Variable variable;
	private Program program;

    public VariableCommentDialog(FunctionPlugin plugin) {
        super(plugin);
    }
    
    /**
     * Display this dialog.
     *  
     * @param theVariable The variable for which to show the comment.
     */
    void showDialog(Program theProgram, Variable theVariable) {
        this.program = theProgram;
        String type = (theVariable instanceof Parameter) ? "Parameter" : "Local Variable";
		setTitle("Set " + type + " Comment: "+ theVariable.getName()); 
        setHelpLocation(new HelpLocation(plugin.getName(), "Edit_Variable_Comment"));
		this.variable = theVariable;
        showDialog(theVariable.getComment());
    }
    
    @Override
    protected void doApply(String comment) {
		plugin.execute(program, new SetVariableCommentCmd(variable, comment));    	
    }
}
