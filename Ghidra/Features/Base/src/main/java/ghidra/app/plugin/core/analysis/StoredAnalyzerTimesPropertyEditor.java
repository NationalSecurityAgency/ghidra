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

import java.awt.*;
import java.beans.PropertyEditorSupport;

import javax.swing.*;

import docking.widgets.label.GDLabel;
import ghidra.framework.options.CustomOptionsEditor;
import ghidra.util.layout.PairLayout;

/**
 * <code>StoredAnalyzerTimesPropertyEditor</code> implements a custom option
 * editor panel for {@link StoredAnalyzerTimes}.  Ability to edit values
 * is disabled with panel intended for display purpose only.
 */
public class StoredAnalyzerTimesPropertyEditor extends PropertyEditorSupport
		implements CustomOptionsEditor {

	private StoredAnalyzerTimes times;

	@Override
	public boolean supportsCustomEditor() {
		return true;
	}

	@Override
	public String[] getOptionNames() {
		if (times == null) {
			return new String[0];
		}
		return times.getTaskNames();
	}

	@Override
	public String[] getOptionDescriptions() {
		return null;
	}

	@Override
	public void setValue(Object value) {
		if (!(value instanceof StoredAnalyzerTimes)) {
			return;
		}

		times = (StoredAnalyzerTimes) value;
		firePropertyChange();
	}

	@Override
	public Object getValue() {
		return times.clone();
	}

	@Override
	public Component getCustomEditor() {
		return buildEditor();
	}

	/**
	 * Build analysis time panel showing all task names and corresponding
	 * cumulative times in seconds.  Edit ability is disabled.
	 * @return options panel
	 */
	private Component buildEditor() {

		if (times == null || times.isEmpty()) {
			JPanel panel = new JPanel(new FlowLayout());
			panel.add(new JLabel("No Data Available"));
			return panel;
		}

		JPanel panel = new JPanel(new PairLayout(6, 10));
		
		panel.add(new GDLabel(""));
		GDLabel label = new GDLabel("seconds", SwingConstants.RIGHT);
		panel.add(label);

		for (String taskName : getOptionNames()) {
			label = new GDLabel(taskName, SwingConstants.RIGHT);
			label.setToolTipText(taskName);
			panel.add(label);
			
			Long timeMS = times.getTime(taskName); 
			if (timeMS == null) {
				continue;
			}

			JTextField valueField = new JTextField(StoredAnalyzerTimes.formatTimeMS(timeMS));
			valueField.setEditable(false);
			valueField.setHorizontalAlignment(SwingConstants.RIGHT);
			panel.add(valueField);
		}

		label = new GDLabel("TOTAL", SwingConstants.RIGHT);
		label.setFont(label.getFont().deriveFont(Font.BOLD));
		panel.add(label);

		JTextField valueField =
			new JTextField(StoredAnalyzerTimes.formatTimeMS(times.getTotalTime()));
		valueField.setEditable(false);
		valueField.setHorizontalAlignment(SwingConstants.RIGHT);
		valueField.setBorder(BorderFactory.createLineBorder(Color.black, 2));
		panel.add(valueField);

		return panel;
	}



}
