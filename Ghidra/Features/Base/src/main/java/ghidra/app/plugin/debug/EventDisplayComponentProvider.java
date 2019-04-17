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
package ghidra.app.plugin.debug;

import java.awt.Point;
import java.util.Date;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.framework.plugintool.*;
import ghidra.program.util.ProgramLocation;
import resources.ResourceManager;

public class EventDisplayComponentProvider extends ComponentProviderAdapter {
	private JTextArea textArea;
	private JScrollPane scrollPane;
	private JViewport viewport;
	private Point bottom = new Point(0, 10000);
	private DockingAction clearAction;

	public EventDisplayComponentProvider(PluginTool tool, String name) {
		super(tool, name, name);
		textArea = new JTextArea(10, 80);
		textArea.setEditable(true);
		scrollPane = new JScrollPane(textArea);
		viewport = scrollPane.getViewport();

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setTitle("Plugin Event Display");
		setVisible(true);
		createAction();
	}

	@Override
	public JComponent getComponent() {
		return scrollPane;
	}

	public void processEvent(PluginEvent event) {
		String date = new Date().toString();

		textArea.append(date + "     " + event.toString());
		printLocationDetails(event);
		textArea.append("\n");
		viewport.setViewPosition(bottom);
	}

	private void printLocationDetails(PluginEvent event) {
		if (event instanceof ProgramLocationPluginEvent) {
			ProgramLocationPluginEvent l = (ProgramLocationPluginEvent) event;
			ProgramLocation location = l.getLocation();
			textArea.append("\t" + location.toString());
			textArea.append("\n");
		}
	}

	private void createAction() {
		clearAction = new DockingAction("Clear Display", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};

		clearAction.markHelpUnnecessary();
		clearAction.setEnabled(true);
		ImageIcon icon = ResourceManager.loadImage("images/erase16.png");
		clearAction.setToolBarData(new ToolBarData(icon));
		addLocalAction(clearAction);
	}

	private void clear() {
		textArea.setText("");
	}
}
