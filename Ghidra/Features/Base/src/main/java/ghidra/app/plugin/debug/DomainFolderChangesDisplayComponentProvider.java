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
package ghidra.app.plugin.debug;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Msg;

import java.awt.Point;
import java.util.Date;

import javax.swing.*;

import resources.ResourceManager;
import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;

public class DomainFolderChangesDisplayComponentProvider extends ComponentProviderAdapter {
	private JTextArea textArea;
	private JScrollPane scrollPane;
	private JViewport viewport;
	private Point bottom = new Point(0, 10000);
	private DockingAction clearAction;

	public DomainFolderChangesDisplayComponentProvider(PluginTool tool, String name) {
		super(tool, name, name);
		textArea = new JTextArea(10, 80);
		textArea.setEditable(true);
		scrollPane = new JScrollPane(textArea);
		viewport = scrollPane.getViewport();
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setTitle("Domain Folder Changes Display");
		setVisible(true);
		createAction();
	}

	@Override
	public JComponent getComponent() {
		return scrollPane;
	}

	public void addText(String text) {
		String date = new Date().toString();
		text = date + "     " + text;
		Msg.debug(this, text);
		textArea.append(text);
		textArea.append("\n");
		viewport.setViewPosition(bottom);
	}

	private void createAction() {
		clearAction = new DockingAction("Clear Display", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};
		clearAction.setEnabled(true);
		ImageIcon icon = ResourceManager.loadImage("images/erase16.png");
		clearAction.setToolBarData(new ToolBarData(icon));
		addLocalAction(clearAction);
	}

	private void clear() {
		textArea.setText("");
	}
}
