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

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import generic.theme.GIcon;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import resources.Icons;

public class DomainEventComponentProvider extends ComponentProviderAdapter {
	final static int LIMIT = 200;
	private final static Icon ICON = new GIcon("icon.plugin.debug.domaineventviewer.provider");

	private JTextArea textArea;
	private JScrollPane scrollPane;
	private DockingAction clearAction;
	private List<String> eventList;

	public DomainEventComponentProvider(PluginTool tool, String owner) {
		super(tool, "Domain Events", owner);
		eventList = new ArrayList<>();

		textArea = new JTextArea(10, 80);
		textArea.setEditable(false);
		scrollPane = new JScrollPane(textArea);

		createAction();
		setIcon(ICON);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setTitle("Domain Object Event Display");
		setVisible(true);
	}

	@Override
	public JComponent getComponent() {
		return scrollPane;
	}

	@Override
	public void componentHidden() {
		clear();
	}

	private void createAction() {
		clearAction = new DockingAction("Clear Display", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clear();
			}
		};

		clearAction.markHelpUnnecessary();
		clearAction.setEnabled(true);
		Icon icon = Icons.CLEAR_ICON;
		clearAction.setToolBarData(new ToolBarData(icon));
		addLocalAction(clearAction);
	}

	private void clear() {
		textArea.setText("");
		eventList.clear();
	}

	void displayEvent(String eventStr) {

		eventList.add(eventStr);
		if (eventList.size() < LIMIT) {
			int caretPos = textArea.getCaretPosition();
			textArea.append(eventStr);
			textArea.setCaretPosition(caretPos + eventStr.length());
		}
		else {
			if (eventList.size() > LIMIT) {
				List<String> list = eventList.subList(100, eventList.size() - 1);
				eventList = new ArrayList<>(list);
			}
			textArea.setText("");
			int length = 0;
			for (String str : eventList) {
				textArea.append(str);
				length += str.length();
			}
			textArea.setCaretPosition(length);
		}
	}

}
