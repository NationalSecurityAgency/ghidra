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
package ghidra.app.plugin.processors.sleigh;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.JComponent;

import ghidra.framework.options.*;
import ghidra.program.database.ProgramDB;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class SpecExtensionEditor implements OptionsEditor, PropertyChangeListener {

	private ProgramDB program;
	private PropertyChangeListener listener;
	private SpecExtensionPanel panel;

	public SpecExtensionEditor(ProgramDB program) {
		this.program = program;
	}

	@Override
	public void apply() throws InvalidInputException {
		panel.apply(TaskMonitor.DUMMY);
	}

	@Override
	public void cancel() {
		panel.cancel();
	}

	@Override
	public void reload() {
		// doesn't respond to reload
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.listener = listener;
	}

	@Override
	public JComponent getEditorComponent(Options options, EditorStateFactory editorStateFactory) {
		panel = new SpecExtensionPanel(program, this);
		return panel;
	}

	@Override
	public void dispose() {
		// stub
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (listener != null) {
			listener.propertyChange(evt);
		}
	}

}
