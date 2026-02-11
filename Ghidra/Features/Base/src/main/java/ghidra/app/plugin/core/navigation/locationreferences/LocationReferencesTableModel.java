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
package ghidra.app.plugin.core.navigation.locationreferences;

import java.awt.*;
import java.util.*;

import javax.swing.*;
import javax.swing.text.View;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.search.SearchLocationContext;
import docking.widgets.table.GTableCellRenderingData;
import generic.theme.GThemeDefaults.Colors;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.AbstractLayoutManager;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.AddressPreviewTableModel;
import ghidra.util.table.column.AbstractGhidraColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;
import utility.function.Callback;

/**
 * A table model that shows the same contents as the {@link AddressPreviewTableModel}, but will
 * also add a references table column when the underlying data contains references.  This model
 * uses data provided by a {@link LocationDescriptor}, which is contained by the given
 * {@link LocationReferencesProvider}.
 * <p>
 * This model also adds the functionality for clients to know when the model has finished loading
 * and it also allows users to reload the data.
 */
class LocationReferencesTableModel extends AddressBasedTableModel<LocationReference> {

	private LocationReferencesProvider provider;
	private boolean initialized = false;
	private boolean performFullReload = false;

	LocationReferencesTableModel(LocationReferencesProvider locationReferencesProvider) {
		super("References", locationReferencesProvider.getTool(),
			locationReferencesProvider.getProgram(), null, true);
		this.provider = locationReferencesProvider;

		addTableColumn(new ContextTableColumn());
	}

	@Override
	protected void doLoad(Accumulator<LocationReference> accumulator, TaskMonitor monitor)
			throws CancelledException {

		LocationDescriptor locationDescriptor = provider.getLocationDescriptor();

		// do this here so that the search is always up-to-date with the options, even if
		// the descriptor is cached
		locationDescriptor.setUseDynamicSearching(provider.useDynamicDataTypeSearching());

		locationDescriptor.getReferences(accumulator, monitor, performFullReload);
		initialized = true;
		performFullReload = false; // no need to perform full reloads unless explicitly set to
	}

	private Collection<Address> toAddresses(Iterable<LocationReference> references) {
		Set<Address> set = new HashSet<>();
		for (LocationReference locationReference : references) {
			set.add(locationReference.getLocationOfUse());
		}
		return set;
	}

	Collection<Address> getReferenceAddresses() {
		return toAddresses(getAllData());
	}

	boolean isInitialized() {
		return initialized;
	}

	// overridden to change initialization state, since clients need to know when this model
	// is finished loading
	@Override
	public void reload() {
		initialized = false;
		super.reload();
	}

	// this reload will signal the underlying model to perform a full reload of its data,
	// rather than just using the cached data
	void fullReload() {
		performFullReload = true;
		reload();
	}

	@Override
	public Address getAddress(int row) {
		return getRowObject(row).getLocationOfUse();
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int column) {

		LocationReference ref = getRowObject(row);
		ProgramLocation location = ref.getProgramLocation();
		if (location != null) {
			return location;
		}

		return super.getProgramLocation(row, column);
	}

//==================================================================================================
//  Inner Classes
//==================================================================================================

	private class ContextTableColumn
			extends AbstractProgramBasedDynamicTableColumn<LocationReference, LocationReference> {

		private static final String OFFCUT_STRING = "<< OFFCUT >>";
		private static final Callback DUMMY_CALLBACK = () -> {
			// dummy
		};

		private Comparator<LocationReference> comparator = new ContextComparator();
		private ContextCellRenderer renderer = new ContextCellRenderer();

		@Override
		public LocationReference getValue(LocationReference rowObject, Settings settings, Program p,
				ServiceProvider sp) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public String getColumnName() {
			return "Context";
		}

		@Override
		public String getColumnDescription() {
			return "<html>Provides information about the references, such as<br>" +
				"the reference type (for applied references) or the context<br>" +
				"of use for discovered references";
		}

		@Override
		public Comparator<LocationReference> getComparator() {
			return comparator;
		}

		@Override
		public GColumnRenderer<LocationReference> getColumnRenderer() {
			return renderer;
		}

		private String getCellDisplayText(LocationReference rowObject) {
			String refTypeString = getRefTypeString(rowObject, DUMMY_CALLBACK);
			if (refTypeString != null) {
				return refTypeString;
			}

			SearchLocationContext context = rowObject.getContext();
			return context.getPlainText();
		}

		private String getRefTypeString(LocationReference rowObject, Callback offcutCallback) {
			String refType = rowObject.getRefTypeString();
			if (!StringUtils.isBlank(refType)) {
				String trailingText = "";
				if (rowObject.isOffcutReference()) {
					offcutCallback.call();
					trailingText = OFFCUT_STRING;
				}
				return refType + trailingText;
			}
			return null;
		}

		private class ContextComparator implements Comparator<LocationReference> {

			@Override
			public int compare(LocationReference lr1, LocationReference lr2) {

				/*
				 * Context text may be lines with leading line numbers or other text, such as the 
				 * ref type (e.g., READ, WRITE, etc).   Further, the table's results may include 
				 * some matches with line numbers and some without.
				 */

				// Use line numbers when both clients have them, as string integer comparisons do not 
				// naturally sort by integer value.
				SearchLocationContext c1 = lr1.getContext();
				int l1 = c1.getLineNumber();
				SearchLocationContext c2 = lr2.getContext();
				int l2 = c2.getLineNumber();
				int result = 0;
				if (l1 >= 0 && l2 >= 0) {
					result = Integer.compare(l1, l2);
					if (result != 0) {
						return result;
					}
				}

				// Either both or not using line numbers or they have the same line number.  Sort by
				// the string display value.
				String t1 = getCellDisplayText(lr1);
				String t2 = getCellDisplayText(lr2);
				result = t1.compareTo(t2);
				if (result != 0) {
					return result;
				}

				// Same text; compare by address
				Address a1 = lr1.getLocationOfUse();
				Address a2 = lr2.getLocationOfUse();
				return a1.compareTo(a2);
			}
		}

		private class ContextCellRenderer extends AbstractGhidraColumnRenderer<LocationReference> {

			private JPanel htmlContainer = new JPanel(new HtmlTruncatingLayout());
			private JLabel ellipsisLabel = new JLabel("...");

			ContextCellRenderer() {
				setHTMLRenderingEnabled(true);
			}

			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				// initialize
				super.getTableCellRendererComponent(data);

				LocationReference rowObject = (LocationReference) data.getRowObject();
				Callback offcutCallback = () -> {
					boolean isSelected = data.isSelected();
					setForeground(getErrorForegroundColor(isSelected));
				};
				String refTypeString = getRefTypeString(rowObject, offcutCallback);
				if (refTypeString != null) {
					setText(refTypeString);
					return this;
				}

				/*
				 	At this point we have html context.  Build a renderer that is a panel with 2
				 	children: the html label (this renderer object) and an ellipsis label that will
				 	be visible as needed. 
				 */
				SearchLocationContext context = rowObject.getContext();
				String html = context.getBoldMatchingText();
				setText(html);

				ellipsisLabel.setOpaque(true);
				ellipsisLabel.setForeground(Colors.FOREGROUND);
				ellipsisLabel.setBackground(getBackground());

				htmlContainer.setBackground(getBackground());
				htmlContainer.removeAll();
				htmlContainer.add(this);
				htmlContainer.add(ellipsisLabel);

				return htmlContainer;
			}

			@Override
			public String getFilterString(LocationReference rowObject, Settings settings) {
				String refTypeString = getRefTypeString(rowObject, DUMMY_CALLBACK);
				if (refTypeString != null) {
					return refTypeString;
				}

				SearchLocationContext context = rowObject.getContext();
				return context.getPlainText();
			}
		}

		/**
		 * A layout manager that positions 2 labels: a leading label with html and a trailing label
		 * with an ellipsis, which may not be visible.  JLabels rendering html will not show an
		 * ellipsis when clipped.   We use these 2 labels here to show when the leading html label's
		 * text is clipped.
		 */
		private class HtmlTruncatingLayout extends AbstractLayoutManager {

			@Override
			public Dimension preferredLayoutSize(Container parent) {

				Dimension d = new Dimension();
				int n = parent.getComponentCount();
				for (int i = 0; i < n; i++) {
					Component c = parent.getComponent(i);
					Dimension cd = c.getPreferredSize();
					d.width += cd.width;
					d.height = Math.max(d.height, cd.height);
				}

				Insets insets = parent.getInsets();
				d.width += insets.left + insets.right;
				d.height += insets.top + insets.bottom;
				return d;
			}

			@Override
			public void layoutContainer(Container parent) {
				// Assumption: the leading component is an html view; the trailing component is a
				// label with an ellipsis

				JComponent c1 = (JComponent) parent.getComponent(0);
				Dimension d = parent.getSize();
				Insets insets = parent.getInsets();
				int width = d.width - insets.left - insets.right;

				View v = (View) c1.getClientProperty("html");
				Insets i = c1.getInsets();
				int availableWidth = width - (i.left + i.right);
				int htmlw = (int) v.getPreferredSpan(View.X_AXIS);

				JLabel c2 = (JLabel) parent.getComponent(1);
				Dimension c2d = c2.getPreferredSize();
				boolean isClipped = htmlw > availableWidth && width != 0;
				if (isClipped) {
					availableWidth -= c2d.width; // save room for ellipsis
					int c2x = availableWidth;
					int c2y = insets.top;
					c2.setBounds(c2x, c2y, c2d.width, c2d.height);
				}

				c2.setVisible(isClipped);

				int c1x = insets.left;
				int c1y = insets.top;
				int cyh = d.height - (i.top + i.bottom);
				c1.setBounds(c1x, c1y, availableWidth, cyh);
			}

		}

	}

}
