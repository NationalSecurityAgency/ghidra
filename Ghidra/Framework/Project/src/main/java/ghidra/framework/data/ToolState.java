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
package ghidra.framework.data;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.*;

/**
 * Container object for the state of the tool to hold an XML element.
 */
public class ToolState {
	protected PluginTool tool;

	private UndoRedoToolState beforeState;
	private UndoRedoToolState afterState;

	/**
	 * Construct a new tool state.
	 * @param tool tool's state to save
	 * @param domainObject the object containing the tool state
	 */
	public ToolState(PluginTool tool, DomainObject domainObject) {
		this.tool = tool;
		beforeState = tool.getUndoRedoToolState(domainObject);
    }

    /**
     * Restore the tool's state after an undo
     */
	public void restoreAfterUndo(DomainObject domainObject) {
		beforeState.restoreTool(domainObject);
	}
	
    /**
     * Restore the tool's state after an undo
     */
	public void restoreAfterRedo(DomainObject domainObject) {
		afterState.restoreTool(domainObject);
	}
	
	public void getAfterState(DomainObject domainObject) {
		afterState = tool.getUndoRedoToolState(domainObject);
	}

}
