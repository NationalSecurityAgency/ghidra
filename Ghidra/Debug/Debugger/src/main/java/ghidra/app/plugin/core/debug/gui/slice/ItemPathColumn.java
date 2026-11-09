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
package ghidra.app.plugin.core.debug.gui.slice;

import java.awt.Font;

import docking.widgets.table.AbstractDynamicTableColumnStub;
import docking.widgets.table.GTableCellRenderingData;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.util.HTMLUtilities;
import ghidra.util.formatter.InstructionHtmlFormatter;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

class ItemPathColumn extends AbstractDynamicTableColumnStub<PathRow, PathRow> {
	private static final InstructionHtmlFormatter INSTRUCTION_FORMATTER =
		new InstructionHtmlFormatter();

	private static final GColumnRenderer<PathRow> RENDERER = new ItemRenderer();

	private static class ItemRenderer extends AbstractGColumnRenderer<PathRow> {
		ItemRenderer() {
			setHTMLRenderingEnabled(true);
		}

		@Override
		protected Font getDefaultFont() {
			return fixedWidthFont;
		}

		@Override
		public String getFilterString(PathRow row, Settings settings) {
			return row == null ? "" : row.getCodeUnit().toString();
		}

		@Override
		protected String getText(GTableCellRenderingData data) {
			PathRow row = (PathRow) data.getValue();
			return switch (row.getCodeUnit()) {
				case Instruction i -> INSTRUCTION_FORMATTER.formatInstruction(i);
				case Data d -> HTMLUtilities.escapeHTML(d.getDefaultValueRepresentation());
				default -> throw new AssertionError();
			};
		}
	}

	@Override
	public String getColumnName() {
		return "Item";
	}

	@Override
	public PathRow getValue(PathRow row, Settings settings, ServiceProvider serviceProvider) {
		return row;
	}

	@Override
	public GColumnRenderer<PathRow> getColumnRenderer() {
		return RENDERER;
	}
}
