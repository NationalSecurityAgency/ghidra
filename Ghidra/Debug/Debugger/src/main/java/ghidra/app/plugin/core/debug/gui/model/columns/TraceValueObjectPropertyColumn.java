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
package ghidra.app.plugin.core.debug.gui.model.columns;

import java.awt.*;
import java.util.Comparator;
import java.util.function.Function;

import javax.swing.JTable;

import docking.widgets.checkbox.GCheckBox;
import docking.widgets.table.*;
import docking.widgets.table.sort.ColumnRenderedValueBackupComparator;
import docking.widgets.table.sort.DefaultColumnComparator;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.model.ColorsModified;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueProperty;
import ghidra.app.plugin.core.debug.gui.model.ObjectTableModel.ValueRow;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.trace.model.Trace;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;

public abstract class TraceValueObjectPropertyColumn<T>
		extends AbstractDynamicTableColumn<ValueRow, ValueProperty<T>, Trace> {

	public class PropertyRenderer extends AbstractGColumnRenderer<ValueProperty<T>>
			implements ColorsModified.InTable {
		{
			setHTMLRenderingEnabled(true);
		}

		@Override
		public String getFilterString(ValueProperty<T> p, Settings settings) {
			return p.getDisplay();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			@SuppressWarnings("unchecked")
			ValueProperty<T> p = (ValueProperty<T>) data.getValue();
			setText(p.getHtmlDisplay());
			setToolTipText(p.getToolTip());

			setForeground(getForegroundFor(data.getTable(), p.isModified(), data.isSelected()));
			return this;
		}

		@Override
		public Color getDiffForeground(JTable p) {
			return diffColor;
		}

		@Override
		public Color getDiffSelForeground(JTable p) {
			return diffColorSel;
		}
	}

	public class BooleanPropertyRenderer extends PropertyRenderer {
		protected GCheckBox cb;
		{
			setLayout(new BorderLayout());
			cb = new GCheckBox();
			cb.setHorizontalAlignment(CENTER);
			cb.setOpaque(false);
			add(cb);
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			@SuppressWarnings("unchecked")
			ValueProperty<T> property = (ValueProperty<T>) data.getValue();
			T value = property.getValue();
			if (value instanceof Boolean b) {
				cb.setVisible(true);
				cb.setSelected(b);
				setText("");
			}
			else {
				cb.setVisible(false);
			}
			return this;
		}

		@Override
		public void validate() {
			synchronized (getTreeLock()) {
				validateTree();
			}
		}
	}

	protected final Class<T> propertyType;
	private final GColumnRenderer<ValueProperty<T>> renderer;
	private final Comparator<ValueProperty<T>> comparator;

	private Color diffColor = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED;
	private Color diffColorSel = DebuggerResources.DEFAULT_COLOR_VALUE_CHANGED_SEL;

	public TraceValueObjectPropertyColumn(Class<T> propertyType) {
		this.propertyType = propertyType;
		this.comparator = newTypedComparator();
		this.renderer = createRenderer();
	}

	public GColumnRenderer<ValueProperty<T>> createRenderer() {
		if (propertyType == Boolean.class) {
			return new BooleanPropertyRenderer();
		}
		return new PropertyRenderer();
	}

	@Override
	public GColumnRenderer<ValueProperty<T>> getColumnRenderer() {
		return renderer;
	}

	@Override
	public Comparator<ValueProperty<T>> getComparator(DynamicColumnTableModel<?> model,
			int columnIndex) {
		return comparator == null ? null
				: comparator.thenComparing(
					new ColumnRenderedValueBackupComparator<>(model, columnIndex));
	}

	public abstract ValueProperty<T> getProperty(ValueRow row);

	@Override
	public ValueProperty<T> getValue(ValueRow rowObject, Settings settings, Trace data,
			ServiceProvider serviceProvider) throws IllegalArgumentException {
		return getProperty(rowObject);
	}

	protected <C extends Comparable<C>> Comparator<ValueProperty<T>> newTypedComparator() {
		if (Comparable.class.isAssignableFrom(propertyType)) {
			@SuppressWarnings("unchecked")
			Class<C> cls = (Class<C>) propertyType.asSubclass(Comparable.class);
			Function<ValueProperty<T>, C> keyExtractor = r -> cls.cast(r.getValue());
			return Comparator.comparing(keyExtractor, new DefaultColumnComparator());
		}
		return null; // Opt for the default filter-string-based comparator
	}

	public void setDiffColor(Color diffColor) {
		this.diffColor = diffColor;
	}

	public void setDiffColorSel(Color diffColorSel) {
		this.diffColorSel = diffColorSel;
	}
}
