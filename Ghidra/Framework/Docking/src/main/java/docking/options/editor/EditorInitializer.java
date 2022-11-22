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
package docking.options.editor;

import ghidra.framework.ModuleInitializer;
import ghidra.framework.options.EnumEditor;
import ghidra.util.Swing;

import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyEditorManager;
import java.io.File;
import java.util.Date;

public class EditorInitializer implements ModuleInitializer {

	@Override
	public void run() {
		// running this on the Swing thread ensures the SwingThread's ThreadGroupContext is used
		// when PropertyEditorManager obtains the PropertyEditorFinder during registration
		Swing.runNow(this::registerEditors);
	}
	
	private void registerEditors() {
		PropertyEditorManager.registerEditor(String.class, StringEditor.class);
		PropertyEditorManager.registerEditor(Color.class, ColorEditor.class);
		PropertyEditorManager.registerEditor(Font.class, FontEditor.class);
		PropertyEditorManager.registerEditor(Enum.class, EnumEditor.class);
		PropertyEditorManager.registerEditor(Boolean.class, BooleanEditor.class);
		PropertyEditorManager.registerEditor(Date.class, DateEditor.class);
		PropertyEditorManager.registerEditor(Integer.class, IntEditor.class);
		PropertyEditorManager.registerEditor(File.class, FileChooserEditor.class);
	}

	@Override
	public String getName() {
		return "Property Editor Initializer";
	}
}
