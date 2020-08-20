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
package ghidra.util.table.column;

import java.awt.Component;
import java.util.Date;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.util.DateUtils;

/**
 * A renderer for clients that wish to display a {@link Date} as a timestamp with the
 * date and time.
 */
public class DefaultTimestampRenderer extends AbstractGColumnRenderer<Date> {

	@Override
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {

		JLabel label = (JLabel) super.getTableCellRendererComponent(data);
		Date value = (Date) data.getValue();

		if (value != null) {
			label.setText(DateUtils.formatDateTimestamp(value));
		}
		return label;
	}

	@Override
	public String getFilterString(Date t, Settings settings) {
		return DateUtils.formatDateTimestamp(t);
	}

	@Override
	public ColumnConstraintFilterMode getColumnConstraintFilterMode() {
		// This allows for text filtering in the table and date filtering on columns
		return ColumnConstraintFilterMode.ALLOW_ALL_FILTERS;
	}
}
