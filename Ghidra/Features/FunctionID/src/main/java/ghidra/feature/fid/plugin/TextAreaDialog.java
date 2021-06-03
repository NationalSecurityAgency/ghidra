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
package ghidra.feature.fid.plugin;

import javax.swing.*;

import docking.DialogComponentProvider;

/**
 * Dialog for the results of the ingest task.
 */
public class TextAreaDialog extends DialogComponentProvider {
	JDialog outerDialog;

	public TextAreaDialog(String title, String text, boolean modal) {
		super(title, modal);
		addOKButton();
		addWorkPanel(createComponent(text));
	}

	private JComponent createComponent(String text) {
		JTextArea area = new JTextArea(text);
		area.setEditable(false);
		JScrollPane sp = new JScrollPane(area);
		return sp;
	}

	@Override
	protected void okCallback() {
		close();
	}
}
