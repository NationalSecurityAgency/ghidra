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
package ghidra.util.table.field;

import java.awt.Color;
import java.awt.Component;
import java.util.Comparator;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import resources.Icons;

public class MemoryTypeProgramLocationBasedTableColumn
		extends ProgramLocationTableColumnExtensionPoint<ProgramLocation, MemoryBlock> {

	private MemoryTypeRenderer renderer = new MemoryTypeRenderer();
	private Comparator<MemoryBlock> comparator = new MemoryTypeComparator();

	@Override
	public String getColumnName() {
		return "Mem Type";
	}

	@Override
	public MemoryBlock getValue(ProgramLocation rowObject, Settings settings, Program program,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.getBlock(rowObject.getAddress());
		return block;
	}

	@Override
	public ProgramLocation getProgramLocation(ProgramLocation rowObject, Settings settings,
			Program program, ServiceProvider serviceProvider) {
		return rowObject;
	}

	@Override
	public GColumnRenderer<MemoryBlock> getColumnRenderer() {
		return renderer;
	}

	@Override
	public Comparator<MemoryBlock> getComparator() {
		return comparator;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class MemoryTypeRenderer extends AbstractGhidraColumnRenderer<MemoryBlock> {

		private Color disabledColor = Palette.LIGHT_GRAY;
		private GIcon offIcon = (GIcon) Icons.EMPTY_ICON;
		private GIcon onIcon = new GIcon("icon.check");

		MemoryTypeRenderer() {
			setHTMLRenderingEnabled(true);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {

			JLabel theRenderer = (JLabel) super.getTableCellRendererComponent(data);

			Object value = data.getValue();

			if (value == null) {
				return this;
			}

			MemoryBlock block = (MemoryBlock) value;

			StringBuilder buffy = new StringBuilder("<html>");
			StringBuilder tooltipBuffy = new StringBuilder("<html>");
			asString(block, buffy, tooltipBuffy);

			setText(buffy.toString());
			setToolTipText(tooltipBuffy.toString());
			return theRenderer;
		}

		private void asString(MemoryBlock block, StringBuilder buffy, StringBuilder tooltipBuffy) {
			updateForRead(block, buffy, tooltipBuffy);
			updateForWrite(block, buffy, tooltipBuffy);
			updateForExecute(block, buffy, tooltipBuffy);
			updateForVolatile(block, buffy, tooltipBuffy);
		}

		private void updateForVolatile(MemoryBlock block, StringBuilder buffy,
				StringBuilder tooltipBuffy) {

			if (block.isVolatile()) {
				buffy.append("<b>V</b>");
				tooltipBuffy.append("<image src=\"" + onIcon.getUrl() + "\">");
			}
			else {
				buffy.append(HTMLUtilities.colorString(disabledColor, "V"));
				tooltipBuffy.append("<image src=\"" + offIcon.getUrl() + "\">");
			}

			tooltipBuffy.append(HTMLUtilities.spaces(2)).append("Volatile<br>");
		}

		private void updateForExecute(MemoryBlock block, StringBuilder buffy,
				StringBuilder tooltipBuffy) {

			if (block.isExecute()) {
				buffy.append("<b>E</b>");
				tooltipBuffy.append("<image src=\"" + onIcon.getUrl() + "\">");
			}
			else {
				buffy.append(HTMLUtilities.colorString(disabledColor, "E"));
				tooltipBuffy.append("<image src=\"" + offIcon.getUrl() + "\">");
			}
			tooltipBuffy.append(HTMLUtilities.spaces(2)).append("Execute<br>");
		}

		private void updateForWrite(MemoryBlock block, StringBuilder buffy,
				StringBuilder tooltipBuffy) {

			if (block.isWrite()) {
				buffy.append("<b>W</b>");
				tooltipBuffy.append("<image src=\"" + onIcon.getUrl() + "\">");
			}
			else {
				buffy.append(HTMLUtilities.colorString(disabledColor, "W"));
				tooltipBuffy.append("<image src=\"" + offIcon.getUrl() + "\">");
			}
			tooltipBuffy.append(HTMLUtilities.spaces(2)).append("Write<br>");
		}

		private void updateForRead(MemoryBlock block, StringBuilder buffy,
				StringBuilder tooltipBuffy) {

			if (block.isRead()) {
				buffy.append("<b>R</b>");
				tooltipBuffy.append("<image src=\"" + onIcon.getUrl() + "\">");
			}
			else {
				buffy.append(HTMLUtilities.colorString(disabledColor, "R"));
				tooltipBuffy.append("<image src=\"" + offIcon.getUrl() + "\">");
			}
			tooltipBuffy.append(HTMLUtilities.spaces(2)).append("Read<br>");
		}

		@Override
		public String getFilterString(MemoryBlock t, Settings settings) {
			if (t == null) {
				return "";
			}

			StringBuilder buffy = new StringBuilder("<html>");
			StringBuilder tooltipBuffy = new StringBuilder("<html>");
			asString(t, buffy, tooltipBuffy);
			return buffy.toString();
		}
	}

	private class MemoryTypeComparator implements Comparator<MemoryBlock> {
		@Override
		public int compare(MemoryBlock o1, MemoryBlock o2) {
			return o1.getPermissions() - o2.getPermissions();
		}
	}
}
