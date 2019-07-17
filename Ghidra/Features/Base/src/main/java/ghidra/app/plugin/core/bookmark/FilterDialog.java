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
package ghidra.app.plugin.core.bookmark;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.app.util.HelpTopics;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;
import ghidra.util.layout.VerticalLayout;

class FilterDialog extends DialogComponentProvider {
	private BookmarkProvider provider;
	private GCheckBox[] buttons;
	private BookmarkType[] types;

	FilterDialog(BookmarkProvider provider, Program p) {
		super("Bookmark Filter", true, false, true, false);
		setHelpLocation(new HelpLocation(HelpTopics.BOOKMARKS, "Filter_Dialog"));
		this.provider = provider;
		addWorkPanel(buildPanel(p));
		addOKButton();
		addCancelButton();
	}

	private JComponent buildPanel(Program program) {
		JPanel p = new JPanel(new VerticalLayout(20));
		p.add(getTypesPanel(program));
		return p;
	}

	private JPanel getTypesPanel(Program program) {
		BookmarkManager bmMgr = program.getBookmarkManager();
		types = bmMgr.getBookmarkTypes();
		buttons = new GCheckBox[types.length];
		JPanel panel = new JPanel(new PairLayout(5, 20));
		panel.setBorder(BorderFactory.createTitledBorder("Include Bookmark Types"));
		for (int i = 0; i < types.length; i++) {
			buttons[i] = new GCheckBox();
			JPanel p = new JPanel(new BorderLayout());
			p.add(buttons[i], BorderLayout.WEST);
			buttons[i].setSelected(provider.isShowingType(types[i].getTypeString()));
			JLabel l =
				new GLabel(types[i].getTypeString(), types[i].getIcon(), SwingConstants.LEFT);
			p.add(l, BorderLayout.CENTER);
			panel.add(p);
		}
		return panel;
	}

	@Override
	protected void okCallback() {
		List<String> typesList = new ArrayList<>(types.length);
		for (int i = 0; i < types.length; i++) {
			if (buttons[i].isSelected()) {
				typesList.add(types[i].getTypeString());
			}
		}
		provider.setFilterTypes(typesList);
		close();
	}

	//for testing
	void setFilter(String filterName, boolean state) {
		for (int i = 0; i < types.length; i++) {
			if (types[i].getTypeString().equals(filterName)) {
				buttons[i].setSelected(state);
			}
		}
	}
}
