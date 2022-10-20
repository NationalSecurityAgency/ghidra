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
package docking.widgets.table;

import java.awt.Component;
import java.awt.Graphics;

import generic.Span;
import generic.Span.SpanSet;
import ghidra.docking.settings.Settings;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class SpanSetTableCellRenderer<N extends Number>
		extends AbstractGColumnRenderer<SpanSet<N, ?>> implements SpannedRenderer<N> {
	protected DoubleSpan fullRangeDouble = new DoubleSpan(0, 1);
	protected double span = 1;

	protected Span<N, ?> fullRange;
	protected SpanSet<N, ?> dataRangeSet;

	@Override
	public void setFullRange(Span<N, ?> fullRange) {
		this.fullRange = fullRange;
		this.fullRangeDouble = SpannedRenderer.validateViewRange(fullRange);
		this.span = this.fullRangeDouble.max() - this.fullRangeDouble.min();
	}

	@Override
	public String getFilterString(SpanSet<N, ?> t, Settings settings) {
		return "";
	}

	@Override
	@SuppressWarnings("unchecked")
	public Component getTableCellRendererComponent(GTableCellRenderingData data) {
		this.dataRangeSet = (SpanSet<N, ?>) data.getValue();
		super.getTableCellRendererComponent(data);
		setText("");
		return this;
	}

	@Override
	protected void paintComponent(Graphics parentG) {
		super.paintComponent(parentG);
		if (dataRangeSet == null || dataRangeSet.isEmpty()) {
			return;
		}

		Graphics g = parentG.create();
		g.setColor(getForeground());
		for (Span<N, ?> span : dataRangeSet.spans()) {
			paintRange(g, span);
		}
	}

	@Override
	public Span<N, ?> getFullRange() {
		return fullRange;
	}

	@Override
	public DoubleSpan getFullRangeDouble() {
		return fullRangeDouble;
	}

	@Override
	public double getSpan() {
		return span;
	}
}
