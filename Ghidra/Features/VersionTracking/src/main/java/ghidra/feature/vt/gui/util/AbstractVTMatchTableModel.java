/* ###
 * IP: GHIDRA
 * NOTE: This code was extracted from VTMatchTableModel via refactoring.
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
package ghidra.feature.vt.gui.util;

import static ghidra.feature.vt.gui.provider.matchtable.MultipleLabelsRenderer.MultipleLabelsRendererType.DESTINATION;
import static ghidra.feature.vt.gui.provider.matchtable.MultipleLabelsRenderer.MultipleLabelsRendererType.SOURCE;
import static ghidra.feature.vt.gui.util.MungedAssocationAndMarkupItemStatus.*;

import java.awt.Color;
import java.awt.Component;
import java.util.*;

import javax.swing.JLabel;

import docking.widgets.table.GTableCellRenderingData;
import docking.widgets.table.TableFilter;
import ghidra.app.util.SymbolInspector;
import ghidra.docking.settings.Settings;
import ghidra.feature.vt.api.impl.VTProgramCorrelatorInfo;
import ghidra.feature.vt.api.main.*;
import ghidra.feature.vt.api.util.EmptyVTSession;
import ghidra.feature.vt.gui.editors.DisplayableAddress;
import ghidra.feature.vt.gui.filters.Filter;
import ghidra.feature.vt.gui.filters.Filter.FilterShortcutState;
import ghidra.feature.vt.gui.plugin.VTController;
import ghidra.feature.vt.gui.provider.markuptable.DisplayableListingAddress;
import ghidra.feature.vt.gui.provider.matchtable.*;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.column.AbstractGColumnRenderer;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractVTMatchTableModel extends AddressBasedTableModel<VTMatch> {

	protected Comparator<VTMatch> markupStatusColumnComparator = new MarkupStatusColumnComparator();
	protected VTSession session;

	private Set<Filter<VTMatch>> allFilters = new HashSet<>();
	protected final VTController controller;

	public AbstractVTMatchTableModel(String title, VTController controller) {
		super(title, controller.getServiceProvider(), null, null);
		this.controller = controller;
	}

	public void sessionChanged() {
		cancelAllUpdates();
		VTSession newSession = controller.getSession();
		if (newSession == null) {
			newSession = new EmptyVTSession();
		}
		setSession(newSession);
	}

	private void setSession(VTSession session) {
		this.session = session;
		super.setProgram(session.getSourceProgram());
		reload();
	}

	@Override
	public Address getAddress(int row) {
		VTMatch match = getRowObject(row);
		VTAssociation association = match.getAssociation();
		return association.getSourceAddress();
	}

	@Override
	protected abstract void doLoad(Accumulator<VTMatch> accumulator, TaskMonitor monitor)
			throws CancelledException;

	@Override
	public void clearData() {
		super.clearData();
	}

	private List<Filter<VTMatch>> getFilters() {
		List<Filter<VTMatch>> appliedFilters = new ArrayList<>();
		for (Filter<VTMatch> filter : allFilters) {
			FilterShortcutState state = filter.getFilterShortcutState();
			if (state == FilterShortcutState.NEVER_PASSES) {
				// we have found a filter that will never pass; signal that all filtering will
				// fail by returning null (the client of this code must know that: null is a 
				// special case and that no filtering is required; all items will fail the filter)
				return null;
			}

			if (state == FilterShortcutState.REQUIRES_CHECK) {

				// we must copy the filter so that changes from the UI do not affect the current
				// filter operation (that would defeat the 'isSubFilterOf' logic
				Filter<VTMatch> copy = filter.createCopy();
				appliedFilters.add(copy);
			}
		}
		return appliedFilters;
	}

	public void updateFilter() {
		rebuildFilter(); // this will trigger a call to reFilter()
	}

	public void addFilter(Filter<VTMatch> filter) {
		allFilters.add(filter);
		rebuildFilter();
	}

	private void rebuildFilter() {
		List<Filter<VTMatch>> appliedFilters = getFilters();
		MatchTablePassthroughFilter passThroughFilter =
			new MatchTablePassthroughFilter(appliedFilters);
		setTableFilter(passThroughFilter);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private static class MatchTablePassthroughFilter implements TableFilter<VTMatch> {

		private List<Filter<VTMatch>> appliedFilters;

		MatchTablePassthroughFilter(List<Filter<VTMatch>> appliedFilters) {
			this.appliedFilters = appliedFilters;
		}

		@Override
		public boolean acceptsRow(VTMatch match) {

			if (appliedFilters == null) {
				// null implies that all items will fail to filter, as one or more of the filters is
				// in a state where nothing will pass
				return false;
			}

			if (appliedFilters.isEmpty()) {
				return true;
			}

			if (rowMatchesFilters(appliedFilters, match)) {
				return true;
			}

			return false;
		}

		private boolean rowMatchesFilters(List<Filter<VTMatch>> filters, VTMatch match) {
			for (Filter<VTMatch> filter : filters) {
				if (!filter.passesFilter(match)) {
					return false; // if any filter doesn't match then we fail
				}
			}
			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {

			if (!(tableFilter instanceof MatchTablePassthroughFilter)) {
				return false;
			}

			MatchTablePassthroughFilter otherMatchFilter =
				(MatchTablePassthroughFilter) tableFilter;
			if (appliedFilters == null || otherMatchFilter.appliedFilters == null) {
				// null is a special case where all items fail to pass the filter
				return false;
			}

			if (appliedFilters.size() != otherMatchFilter.appliedFilters.size()) {
				return false;
			}

			int n = appliedFilters.size();
			for (int i = 0; i < n; i++) {
				Filter<VTMatch> myFilter = appliedFilters.get(i);
				Filter<VTMatch> otherFilter = otherMatchFilter.appliedFilters.get(i);
				if (!myFilter.isSubFilterOf(otherFilter)) {
					return false;
				}
			}

			return true;
		}

		@Override
		public int hashCode() {
			// not meant to put in hashing structures; the data for equals changes
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean equals(Object obj) {
			// For now we don't support equals(); if this filter gets re-created, 
			// then the table must be re-filtered.  If we decide to implement this method, then 
			// we must also implement equals() on the filters used by this filter.
			return this == obj;
		}
	}

	static class MarkupStatusColumnComparator implements Comparator<VTMatch> {
		@Override
		public int compare(VTMatch o1, VTMatch o2) {
			// for this column we want to compare on the status
			VTAssociation association1 = o1.getAssociation();
			VTAssociation association2 = o2.getAssociation();
			VTAssociationStatus status1 = association1.getStatus();
			VTAssociationStatus status2 = association2.getStatus();
			int result = status1.compareTo(status2);
			if (result == 0) {
				VTAssociationMarkupStatus markupStatus1 = association1.getMarkupStatus();
				VTAssociationMarkupStatus markupStatus2 = association2.getMarkupStatus();
				result = markupStatus1.compareTo(markupStatus2);
			}
			return result;
		}
	}

	public static class SourceAddressComparator implements Comparator<VTMatch> {
		@Override
		public int compare(VTMatch o1, VTMatch o2) {
			VTAssociation association1 = o1.getAssociation();
			VTAssociation association2 = o2.getAssociation();
			Address address1 = association1.getSourceAddress();
			Address address2 = association2.getSourceAddress();
			return address1.compareTo(address2);
		}
	}

	public static class DestinationAddressComparator implements Comparator<VTMatch> {
		@Override
		public int compare(VTMatch o1, VTMatch o2) {
			VTAssociation association1 = o1.getAssociation();
			VTAssociation association2 = o2.getAssociation();
			Address address1 = association1.getDestinationAddress();
			Address address2 = association2.getDestinationAddress();
			return address1.compareTo(address2);
		}
	}

	public static class StatusTableColumn extends
			AbstractProgramBasedDynamicTableColumn<VTMatch, MungedAssocationAndMarkupItemStatus> {

		@Override
		public String getColumnName() {
			return "Status";
		}

		@Override
		public MungedAssocationAndMarkupItemStatus getValue(VTMatch rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {

			VTAssociation association = rowObject.getAssociation();
			VTAssociationStatus associationStatus = association.getStatus();

			switch (associationStatus) {
				case ACCEPTED:
					VTAssociationMarkupStatus markupStatus = association.getMarkupStatus();
					if (markupStatus.isFullyApplied()) {
						return ACCEPTED_FULLY_APPLIED;
					}
					else if (markupStatus.hasErrors()) {
						return ACCEPTED_HAS_ERRORS;
					}
					else if (markupStatus.hasUnexaminedMarkup()) {
						return ACCEPTED_SOME_UNEXAMINED;
					}
					return ACCEPTED_NO_UNEXAMINED;
				case AVAILABLE:
					return AVAILABLE;
				case BLOCKED:
					return BLOCKED;
				case REJECTED:
					return REJECTED;
			}

			throw new IllegalArgumentException("Unexpected and unhandled VTAssociationStatus");
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}

	// Status
	public static class AppliedMarkupStatusBatteryTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, VTMatch> {

		private MatchMarkupStatusBatteryRenderer renderer = new MatchMarkupStatusBatteryRenderer();

		@Override
		public String getColumnName() {
			return "Markup Status - Deprecated";
		}

		@Override
		public VTMatch getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 40;
		}

		@Override
		public GColumnRenderer<VTMatch> getColumnRenderer() {
			return renderer;
		}
	}

	// Status
	public static class AppliedMarkupStatusTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, VTMatch> {

		private MatchMarkupStatusRenderer renderer = new MatchMarkupStatusRenderer();

		@Override
		public String getColumnName() {
			return "Markup Status";
		}

		@Override
		public VTMatch getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 60;
		}

		@Override
		public GColumnRenderer<VTMatch> getColumnRenderer() {
			return renderer;
		}
	}

	// Match Type
	public static class MatchTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getColumnDescription() {
			return "Type - type of match";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getAssociation().getType().toString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	public static class ScoreTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, VTScore> {

		@Override
		public String getColumnName() {
			return "Score";
		}

		@Override
		public String getColumnDescription() {
			return "Score - score of match similarity";
		}

		@Override
		public VTScore getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			return rowObject.getSimilarityScore();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 55;
		}

		private GColumnRenderer<VTScore> renderer = new AbstractGColumnRenderer<>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				Object value = data.getValue();

				VTScore score = (VTScore) value;
				if (score == null) {
					label.setText("N/A");
				}
				else {
					label.setText(score.getFormattedScore());
				}

				label.setOpaque(true);

				return label;
			}

			@Override
			public String getFilterString(VTScore t, Settings settings) {
				if (t == null) {
					return "N/A";
				}
				return t.getFormattedScore();
			}
		};

		@Override
		public GColumnRenderer<VTScore> getColumnRenderer() {
			return renderer;
		}
	}

	public static class ConfidenceScoreTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, VTScore> {

		@Override
		public String getColumnName() {
			return "Confidence (log10)";
		}

		@Override
		public String getColumnDescription() {
			return "Confidence (log10) - confidence level that the items are a valid match";
		}

		@Override
		public VTScore getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getConfidenceScore();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 55;
		}

		private GColumnRenderer<VTScore> renderer = new AbstractGColumnRenderer<>() {
			@Override
			public Component getTableCellRendererComponent(GTableCellRenderingData data) {

				JLabel label = (JLabel) super.getTableCellRendererComponent(data);

				Object value = data.getValue();

				VTScore score = (VTScore) value;
				if (score == null) {
					label.setText("N/A");
				}
				else {
					label.setText(score.getFormattedLog10Score());
				}
				label.setOpaque(true);

				return label;
			}

			@Override
			public String getFilterString(VTScore t, Settings settings) {
				if (t == null) {
					return "N/A";
				}
				return t.getFormattedLog10Score();
			}
		};

		@Override
		public GColumnRenderer<VTScore> getColumnRenderer() {
			return renderer;
		}
	}

	// Multiple Source Labels Indicator
	public static class MultipleSourceLabelsTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Symbol[]> {

		private MultipleLabelsRenderer renderer = new MultipleLabelsRenderer(SOURCE);

		@Override
		public String getColumnName() {
			return "Multiple Source Labels?";
		}

		@Override
		public GColumnRenderer<Symbol[]> getColumnRenderer() {
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Symbol[] getValue(VTMatch rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			VTAssociation association = rowObject.getAssociation();
			VTController controller = serviceProvider.getService(VTController.class);
			Program sourceProgram = controller.getSourceProgram();
			Address sourceAddress = association.getSourceAddress();
			Symbol[] symbols = sourceProgram.getSymbolTable().getSymbols(sourceAddress);
			return symbols;
		}
	}

	// Source Label
	public static class SourceLabelTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, DisplayableLabel> {

		private SymbolInspector symbolInspector;

		@Override
		public String getColumnName() {
			return "Source Label";
		}

		@Override
		public DisplayableLabel getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(localServiceProvider, null);
			}
			VTAssociation association = rowObject.getAssociation();
			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getSourceSymbol(association);
			return new DisplayableLabel(symbol);
		}

		private GColumnRenderer<DisplayableLabel> labelCellRenderer =
			new AbstractGColumnRenderer<>() {
				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					Object value = data.getValue();

					DisplayableLabel displayableLabel = (DisplayableLabel) value;
					String labelString = displayableLabel.getDisplayString();

					GTableCellRenderingData renderData = data.copyWithNewValue(labelString);

					JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);
					renderer.setToolTipText(null);

					Symbol symbol = displayableLabel.getSymbol();
					if (symbol != null) {
						Namespace parentNamespace = symbol.getParentNamespace();
						if (!parentNamespace.isGlobal()) {
							renderer.setToolTipText(symbol.getName(true));
						}
						if (symbolInspector != null) {
							symbolInspector.setProgram(symbol.getProgram());
							renderer.setForeground(symbolInspector.getColor(symbol));
						}
					}
					else {
						renderer.setForeground(Color.RED);
					}

					renderer.setOpaque(true);
					setBold();

					return renderer;
				}

				@Override
				public String getFilterString(DisplayableLabel t, Settings settings) {
					return t.getDisplayString();
				}
			};

		@Override
		public GColumnRenderer<DisplayableLabel> getColumnRenderer() {
			return labelCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	// Source Label
	public static class SourceNamespaceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Source Namespace";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {
			VTAssociation association = rowObject.getAssociation();
			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getSourceSymbol(association);
			if (symbol == null) {
				return "";
			}
			return symbol.getParentNamespace().getName(true);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	// Source Label Type
	public static class SourceLabelSourceTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Source Label Type";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {
			VTAssociation association = rowObject.getAssociation();

			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getSourceSymbol(association);
			if (symbol == null) {
				return "<No Symbol>";
			}
			return symbol.getSource().getDisplayString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	// Source Address
	public static class SourceAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, DisplayableAddress> {

		private SymbolInspector symbolInspector;

		@Override
		public String getColumnName() {
			return "Source Address";
		}

		@Override
		public DisplayableListingAddress getValue(VTMatch rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(serviceProvider, null);
			}
			VTAssociation association = rowObject.getAssociation();
			Address sourceAddress = association.getSourceAddress();
			Program sourceProgram = rowObject.getMatchSet().getSession().getSourceProgram();
			return new DisplayableListingAddress(sourceProgram, sourceAddress);
		}

		private GColumnRenderer<DisplayableAddress> addressCellRenderer =
			new AbstractGColumnRenderer<>() {

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					Object value = data.getValue();

					DisplayableListingAddress displayableAddress =
						(DisplayableListingAddress) value;
					String addressString = displayableAddress.getDisplayString();

					GTableCellRenderingData renderData = data.copyWithNewValue(addressString);

					JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);

					Program program = displayableAddress.getProgram();
					Address address = displayableAddress.getAddress();
					if (!address.isMemoryAddress() && symbolInspector != null) {
						Symbol s = program.getSymbolTable().getPrimarySymbol(address);
						symbolInspector.setProgram(program);
						Color c = (s != null) ? symbolInspector.getColor(s) : Color.RED;
						setForeground(c);
					}
					else if (!program.getMemory().contains(address)) {
						setForeground(Color.RED);
					}

					renderer.setOpaque(true);

					return renderer;
				}

				@Override
				public String getFilterString(DisplayableAddress t, Settings settings) {
					return t.getDisplayString();
				}
			};

		@Override
		public GColumnRenderer<DisplayableAddress> getColumnRenderer() {
			return addressCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	// Multiple Destination Labels Indicator
	public static class MultipleDestinationLabelsTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Symbol[]> {

		private MultipleLabelsRenderer renderer = new MultipleLabelsRenderer(DESTINATION);

		@Override
		public String getColumnName() {
			return "Multiple Dest Labels?";
		}

		@Override
		public GColumnRenderer<Symbol[]> getColumnRenderer() {
			return renderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}

		@Override
		public Symbol[] getValue(VTMatch rowObject, Settings settings, Program data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {

			VTAssociation association = rowObject.getAssociation();
			VTController controller = serviceProvider.getService(VTController.class);
			Program destinationProgram = controller.getDestinationProgram();
			Address destinationAddress = association.getDestinationAddress();
			Symbol[] symbols = destinationProgram.getSymbolTable().getSymbols(destinationAddress);
			return symbols;
		}
	}

	// Destination Label
	public static class DestinationLabelTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, DisplayableLabel> {

		private SymbolInspector symbolInspector;

		@Override
		public String getColumnName() {
			return "Dest Label";
		}

		@Override
		public DisplayableLabel getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(localServiceProvider, null);
			}
			VTAssociation association = rowObject.getAssociation();
			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getDestinationSymbol(association);
			return new DisplayableLabel(symbol);
		}

		private GColumnRenderer<DisplayableLabel> labelCellRenderer =
			new AbstractGColumnRenderer<>() {

				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					Object value = data.getValue();

					DisplayableLabel displayableLabel = (DisplayableLabel) value;
					String labelString = displayableLabel.getDisplayString();

					GTableCellRenderingData renderData = data.copyWithNewValue(labelString);

					JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);
					renderer.setToolTipText(null);

					Symbol symbol = displayableLabel.getSymbol();
					if (symbol != null) {
						Namespace parentNamespace = symbol.getParentNamespace();
						if (!parentNamespace.isGlobal()) {
							renderer.setToolTipText(symbol.getName(true));
						}
						if (symbolInspector != null) {
							symbolInspector.setProgram(symbol.getProgram());
							renderer.setForeground(symbolInspector.getColor(symbol));
						}
					}
					else {
						renderer.setForeground(Color.RED);
					}

					renderer.setOpaque(true);
					setBold();

					return renderer;
				}

				@Override
				public String getFilterString(DisplayableLabel t, Settings settings) {
					return t.getDisplayString();
				}
			};

		@Override
		public GColumnRenderer<DisplayableLabel> getColumnRenderer() {
			return labelCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	// Destination Label
	public static class DestinationNamespaceTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Dest Namespace";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {
			VTAssociation association = rowObject.getAssociation();
			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getDestinationSymbol(association);
			if (symbol == null) {
				return "";
			}
			return symbol.getParentNamespace().getName(true);
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	// Destination Label Type
	public static class DestinationLabelSourceTypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Dest Label Type";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program localProgram,
				ServiceProvider localServiceProvider) throws IllegalArgumentException {

			VTAssociation association = rowObject.getAssociation();
			VTController controller = localServiceProvider.getService(VTController.class);
			Symbol symbol = controller.getDestinationSymbol(association);
			if (symbol == null) {
				return "<No Symbol>";
			}
			return symbol.getSource().getDisplayString();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	// Destination Address
	public static class DestinationAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, DisplayableAddress> {

		private SymbolInspector symbolInspector;

		@Override
		public String getColumnName() {
			return "Dest Address";
		}

		@Override
		public DisplayableListingAddress getValue(VTMatch rowObject, Settings settings,
				Program program, ServiceProvider serviceProvider) throws IllegalArgumentException {
			if (symbolInspector == null) {
				symbolInspector = new SymbolInspector(serviceProvider, null);
			}
			VTAssociation association = rowObject.getAssociation();
			Address destinationAddress = association.getDestinationAddress();
			Program destinationProgram =
				rowObject.getMatchSet().getSession().getDestinationProgram();
			return new DisplayableListingAddress(destinationProgram, destinationAddress);
		}

		private GColumnRenderer<DisplayableAddress> addressCellRenderer =
			new AbstractGColumnRenderer<>() {
				@Override
				public Component getTableCellRendererComponent(GTableCellRenderingData data) {

					Object value = data.getValue();

					DisplayableListingAddress displayableAddress =
						(DisplayableListingAddress) value;
					String addressString = displayableAddress.getDisplayString();

					GTableCellRenderingData renderData = data.copyWithNewValue(addressString);

					JLabel renderer = (JLabel) super.getTableCellRendererComponent(renderData);

					Program program = displayableAddress.getProgram();
					Address address = displayableAddress.getAddress();
					if (!address.isMemoryAddress() && symbolInspector != null) {
						Symbol s = program.getSymbolTable().getPrimarySymbol(address);
						symbolInspector.setProgram(program);
						Color c = (s != null) ? symbolInspector.getColor(s) : Color.RED;
						setForeground(c);
					}
					else if (!program.getMemory().contains(address)) {
						setForeground(Color.RED);
					}

					renderer.setOpaque(true);

					return renderer;
				}

				@Override
				public String getFilterString(DisplayableAddress t, Settings settings) {
					return t.getDisplayString();
				}
			};

		@Override
		public GColumnRenderer<DisplayableAddress> getColumnRenderer() {
			return addressCellRenderer;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 75;
		}
	}

	// Source Length
	public static class SourceLengthTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "Source Length";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getSourceLength();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 35;
		}
	}

	// Destination Length
	public static class DestinationLengthTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "Dest Length";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getDestinationLength();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 35;
		}
	}

	// Delta Length
	public static class LengthDeltaTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "Length Delta";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			int destinationLength = rowObject.getDestinationLength();
			int sourceLength = rowObject.getSourceLength();
			int max = Math.max(destinationLength, sourceLength);
			int min = Math.min(destinationLength, sourceLength);
			return max - min;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}

	// Algorithm column
	public static class AlgorithmTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Algorithm";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			VTMatchSet matchSet = rowObject.getMatchSet();
			VTProgramCorrelatorInfo info = matchSet.getProgramCorrelatorInfo();
			return info.getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 150;
		}
	}

	// Session Number
	public static class SessionNumberTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "Session ID";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			VTMatchSet matchSet = rowObject.getMatchSet();
			int id = matchSet.getID();
			if (id < 1) {
				return null;
			}
			return id;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}

	// Tag
	public static class TagTableColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, String> {

		@Override
		public String getColumnName() {
			return "Tag";
		}

		@Override
		public String getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			VTMatchTag tag = rowObject.getTag();
			if (tag == null) {
				return null;
			}
			return tag.getName();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	public static class ImpliedMatchCountColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "Votes";
		}

		@Override
		public String getColumnDescription() {
			return "Votes - The number of references from from previously accepted " +
				"matches that would suggest that this is a correct match";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return rowObject.getAssociation().getVoteCount();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}

	public static class RelatedMatchCountColumn
			extends AbstractProgramBasedDynamicTableColumn<VTMatch, Integer> {

		@Override
		public String getColumnName() {
			return "# Conflicting";
		}

		@Override
		public String getColumnDescription() {
			return "# Conflicting - The number of unique associations with either" +
				" the same source or same destination address";
		}

		@Override
		public Integer getValue(VTMatch rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			// subtract 1 here because the match itself is always counted in the results
			return rowObject.getAssociation().getRelatedAssociations().size() - 1;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 30;
		}
	}
}
