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
package ghidra.app.plugin.core.analysis;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.JComponent;

import ghidra.framework.options.*;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.InvalidInputException;

class AnalysisOptionsEditor implements OptionsEditor, PropertyChangeListener {

	private PropertyChangeListener listener;
	private AnalysisPanel panel;
	private Program program;

	AnalysisOptionsEditor(Program program) {
		this.program = program;
	}

	@Override
	public void dispose() {
		// stub
	}

	@Override
	public void apply() throws InvalidInputException {
		panel.applyChanges();
	}

	@Override
	public void cancel() {
		// don't care
	}

	@Override
	public void reload() {
		// this component doesn't respond to reloads
	}

	@Override
	public JComponent getEditorComponent(Options options, EditorStateFactory editorStateFactory) {
		panel = new AnalysisPanel(program, editorStateFactory, this);
		return panel;
	}

	@Override
	public void setOptionsPropertyChangeListener(PropertyChangeListener listener) {
		this.listener = listener;
	}

	@Override
	public void propertyChange(PropertyChangeEvent event) {
		if (listener != null) {
			listener.propertyChange(event);
		}
	}

}
