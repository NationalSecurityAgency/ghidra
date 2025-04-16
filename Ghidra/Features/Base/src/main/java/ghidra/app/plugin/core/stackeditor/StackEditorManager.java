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
package ghidra.app.plugin.core.stackeditor;

import java.util.*;

import ghidra.app.plugin.core.compositeeditor.EditorListener;
import ghidra.app.plugin.core.compositeeditor.EditorProvider;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;

/**
 * Manages edit sessions of function stack frames for multiple open programs.
 */
public class StackEditorManager implements EditorListener {

	private HashMap<Function, StackEditorProvider> editorMap;
	private StackEditorManagerPlugin plugin;

	/**
	 * Constructor
	 * @param plugin the plugin that owns this manager.
	 */
	public StackEditorManager(StackEditorManagerPlugin plugin) {
		this.plugin = plugin;
		editorMap = new HashMap<Function, StackEditorProvider>();
	}

	/**
	 * Tells a plugin that it is no longer needed.  The plugin should remove itself
	 * from anything that it is registered to and release any resources.
	 */
	public void dispose() {
		// Close all editors.
		dismissEditors(null);
	}

	/**
	 * Pop up the editor dialog for the given stack frame.
	 * @param function function whose stack frame is to be edited
	 */
	public void edit(Function function) {
		StackEditorProvider editor = editorMap.get(function);
		if (editor != null) {
			plugin.getTool().showComponentProvider(editor.getComponentProvider(), true);
		}
		else {
			editor = new StackEditorProvider(plugin, function);
			editor.addEditorListener(this); // listen for editor closing.
			editorMap.put(function, editor);
		}
	}

	/**
	 * Subclass should override this method if it is interested in
	 * close program events.
	 * @param closedProgram program which was closed
	 */
	protected void programClosed(Program closedProgram) {
		dismissEditors(closedProgram);
	}

	/**
	 * Returns true if there is at least one stack frame editor in use.
	 * @return true if editing stack frame(s).
	 */
	boolean isEditInProgress() {
		return editorMap.size() > 0;
	}

	/**
	 * Dismiss all open stack frame editors for the indicated program.
	 * @param program program whose editors should close
	 */
	void dismissEditors(Program program) {
		List<Function> list = new ArrayList<Function>(editorMap.keySet());
		for (Function function : list) {
			if (program == null || function.getProgram() == program) {
				StackEditorProvider editor = editorMap.get(function);
				editor.dispose();
				editorMap.remove(function);
			}
		}
	}

	/**
	 * Check for any data types being edited for the given data
	 * type manager that is being closed.
	 * if pgm is null then all editors will be checked.
	 * @param program the program whose stack editors are to be checked for changes. 
	 * If null, then check all editors for save.
	 * @return true if all stack editors were resolved and can close now; return
	 * false if the user canceled the save action
	 */
	private boolean checkEditors(Program program) {

		Iterator<Function> iter = editorMap.keySet().iterator();
		while (iter.hasNext()) {
			Function function = iter.next();
			if (program == null || function.getProgram() == program) {
				StackEditorProvider editor = editorMap.get(function);
				editor.show();
				if (editor.needsSave()) {
					if (!editor.checkForSave(true)) {
						return false;
					}
				}
			}
		}
		return true;
	}

	@Override
	public void closed(EditorProvider editor) {
		StackEditorProvider stackEditorProvider = (StackEditorProvider) editor;
		editorMap.remove(stackEditorProvider.getFunction());
	}

	protected boolean canCloseDomainObject(DomainObject dObj) {
		if (!(dObj instanceof Program)) {
			return true;
		}
		return checkEditors((Program) dObj);
	}

	protected boolean canClose() {
		return checkEditors(null);
	}

	protected void close() {
		for (StackEditorProvider editor : editorMap.values()) {
			editor.dispose();
		}
		editorMap.clear();
	}

}
