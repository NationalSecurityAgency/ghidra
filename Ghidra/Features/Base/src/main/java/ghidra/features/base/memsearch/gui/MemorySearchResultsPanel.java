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
package ghidra.features.base.memsearch.gui;

import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.TableModelEvent;

import ghidra.app.nav.Navigatable;
import ghidra.features.base.memsearch.bytesource.AddressableByteSource;
import ghidra.features.base.memsearch.combiner.Combiner;
import ghidra.features.base.memsearch.matcher.SearchData;
import ghidra.features.base.memsearch.scan.Scanner;
import ghidra.features.base.memsearch.searcher.MemoryMatch;
import ghidra.features.base.memsearch.searcher.MemorySearcher;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.*;
import ghidra.util.task.*;

/**
 * Internal panel of the memory search window that manages the display of the search results
 * in a table. This panel also includes most of the search logic as it has direct access to the
 * table for showing the results.
 */
public class MemorySearchResultsPanel extends JPanel {
	private GhidraThreadedTablePanel<MemoryMatch<SearchData>> threadedTablePanel;
	private GhidraTableFilterPanel<MemoryMatch<SearchData>> tableFilterPanel;
	private GhidraTable table;
	private MemoryMatchTableModel tableModel;
	private MemorySearchProvider provider;
	private SearchMarkers markers;

	private boolean hasDeleted;
	private boolean hasCombined;

	MemorySearchResultsPanel(MemorySearchProvider provider, SearchMarkers markers) {
		super(new BorderLayout());
		this.provider = provider;
		this.markers = markers;

		Navigatable navigatable = provider.getNavigatable();
		tableModel = new MemoryMatchTableModel(provider.getTool(), navigatable.getProgram());
		threadedTablePanel = new GhidraThreadedTablePanel<>(tableModel);
		table = threadedTablePanel.getTable();

		table.setActionsEnabled(true);
		table.installNavigation(provider.getTool(), navigatable);
		tableModel.addTableModelListener(this::tableChanged);

		add(threadedTablePanel, BorderLayout.CENTER);
		add(createFilterFieldPanel(), BorderLayout.SOUTH);
		ListSelectionModel selectionModel = threadedTablePanel.getTable().getSelectionModel();
		selectionModel.addListSelectionListener(this::selectionChanged);
	}

	private void tableChanged(TableModelEvent event) {
		markers.loadMarkers(provider.getTitle(), tableModel.getModelData());
	}

	void itemDeleted() {
		hasDeleted = true;
	}

	boolean hasUserChanges() {
		return hasDeleted || hasCombined;
	}

	void providerActivated() {
		markers.makeActiveMarkerSet();
	}

	private void selectionChanged(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		provider.tableSelectionChanged();
	}

	private JComponent createFilterFieldPanel() {
		tableFilterPanel = new GhidraTableFilterPanel<>(table, tableModel);
		tableFilterPanel.setToolTipText("Filter search results");
		return tableFilterPanel;
	}

	public void search(MemorySearcher<SearchData> searcher, Combiner combiner) {
		MemoryMatchTableLoader loader = createLoader(searcher, combiner);
		tableModel.addInitialLoadListener(
			cancelled -> provider.searchAllCompleted(loader.hasResults(), cancelled,
				loader.didTerminateEarly()));
		tableModel.setLoader(loader);
	}

	public void searchOnce(MemorySearcher<SearchData> searcher, Address address, boolean forward) {
		SearchOnceTask task = new SearchOnceTask(forward, searcher, address);
		TaskLauncher.launch(task);
	}

	public void refreshAndMaybeScanForChanges(AddressableByteSource byteSource, Scanner scanner) {
		RefreshAndScanTask task = new RefreshAndScanTask(byteSource, scanner);
		TaskLauncher.launch(task);
	}

	public void refreshAndMaybeScanForChanges(AddressableByteSource byteSource, Scanner scanner,
			List<MemoryMatch<SearchData>> previousResults) {
		RefreshAndScanTask task = new RefreshAndScanTask(byteSource, scanner, previousResults);
		TaskLauncher.launch(task);
	}

	private MemoryMatchTableLoader createLoader(MemorySearcher<SearchData> searcher,
			Combiner combiner) {
		if (!hasResults()) {
			hasDeleted = false;
			return new NewSearchTableLoader(searcher);
		}

		// We have existing results.  Will they be merged?
		if (combiner.isMerge()) {

			// If we have existing results, the combiner determines how the new search results get
			// combined with the existing results.
			// 
			// However, if the combiner is the "Replace" combiner, the results are not combined
			// and only the new results are kept. In this case, it is preferred to use the same
			// loader as if doing an initial search because you get incremental loading and also
			// don't need to copy the existing results to feed to a combiner.
			hasCombined = true;
			List<MemoryMatch<SearchData>> previousResults = tableModel.getModelData();
			return new CombinedMatchTableLoader(searcher, previousResults, combiner);
		}

		// We have results, but we are going to replace them.  A new load of data means any previous
		// manual deletes are now irrelevant
		hasDeleted = false;
		return new NewSearchTableLoader(searcher);
	}

	public boolean hasResults() {
		return tableModel.getRowCount() > 0;
	}

	public void clearResults() {
		tableModel.addInitialLoadListener(b -> provider.searchAllCompleted(true, false, false));
		tableModel.setLoader(new EmptyMemoryMatchTableLoader());
	}

	public int getMatchCount() {
		return tableModel.getRowCount();
	}

	void select(MemoryMatch<SearchData> match) {
		int rowIndex = tableModel.getRowIndex(match);
		if (rowIndex >= 0) {
			threadedTablePanel.getTable().selectRow(rowIndex);
		}
	}

	public GhidraTable getTable() {
		return table;
	}

	public MemoryMatch<SearchData> getSelectedMatch() {
		int row = table.getSelectedRow();
		return row < 0 ? null : tableModel.getRowObject(row);
	}

	public void dispose() {
		markers.dispose();
		tableFilterPanel.dispose();
	}

	MemoryMatchTableModel getTableModel() {
		return tableModel;
	}

	private class SearchOnceTask extends Task {

		private boolean forward;
		private MemorySearcher<SearchData> searcher;
		private Address start;

		public SearchOnceTask(boolean forward, MemorySearcher<SearchData> searcher, Address start) {
			super(forward ? "Search Next" : "Search Previous", true, true, true);
			this.forward = forward;
			this.searcher = searcher;
			this.start = start;
		}

		private void tableLoadComplete(MemoryMatch<SearchData> match, boolean wasCancelled) {
			int rowIndex = tableModel.getRowIndex(match);
			if (rowIndex >= 0) {
				table.selectRow(rowIndex);
				table.scrollToSelectedRow();
				provider.searchOnceCompleted(match, wasCancelled);
			}
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				MemoryMatch<SearchData> match = searcher.findOnce(start, forward, monitor);
				if (match != null) {
					tableModel.addInitialLoadListener(b -> tableLoadComplete(match, b));
					tableModel.addObject(match);
					return;
				}
			}
			catch (Throwable t) {
				// Catch any runtime errors so that we exit task gracefully and don't leave
				// the provider in a stuck "busy" state.
				Msg.showError(this, null, "Error Searching Memory",
					"Unexpected error searching for bytes", t);
			}
			Swing.runLater(() -> provider.searchOnceCompleted(null, monitor.isCancelled()));
		}
	}

	private class RefreshAndScanTask extends Task {

		private AddressableByteSource byteSource;
		private Scanner scanner;
		private List<MemoryMatch<SearchData>> matchList;

		public RefreshAndScanTask(AddressableByteSource byteSource, Scanner scanner) {
			this(byteSource, scanner, tableModel.getModelData());
		}

		public RefreshAndScanTask(AddressableByteSource byteSource, Scanner scanner,
				List<MemoryMatch<SearchData>> matches) {
			super("Refreshing", true, true, true);
			this.byteSource = byteSource;
			this.scanner = scanner;
			this.matchList = matches;
		}

		private void tableLoadComplete(MemoryMatch<SearchData> match) {
			if (match == null) {
				provider.refreshAndScanCompleted(null);
			}
			int rowIndex = tableModel.getRowIndex(match);
			if (rowIndex >= 0) {
				table.selectRow(rowIndex);
				table.scrollToSelectedRow();
			}
			provider.refreshAndScanCompleted(match);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			if (refreshByteValues(monitor, matchList) && scanner != null) {
				performScanFiltering(monitor, matchList);
			}
			else {
				tableModel.fireTableDataChanged();  // some data bytes may have changed, repaint
				provider.refreshAndScanCompleted(null);
			}
		}

		private boolean refreshByteValues(TaskMonitor monitor,
				List<MemoryMatch<SearchData>> matches) {
			try {
				byteSource.invalidate();	// clear any caches before refreshing byte values
				monitor.initialize(matches.size(), "Refreshing...");
				for (MemoryMatch<SearchData> match : matches) {
					byte[] bytes = new byte[match.getLength()];
					byteSource.getBytes(match.getAddress(), bytes, bytes.length);
					match.updateBytes(bytes);
					monitor.incrementProgress();
					if (monitor.isCancelled()) {
						return false;
					}
				}
				return true;
			}
			catch (Throwable t) {
				// Catch any runtime errors so that we exit task gracefully and don't leave
				// the provider in a stuck "busy" state.
				Msg.showError(this, null, "Unexpected error refreshing bytes", t);
			}
			return false;
		}

		private void performScanFiltering(TaskMonitor monitor,
				List<MemoryMatch<SearchData>> matches) {
			monitor.initialize(matches.size(), "Scanning for changes...");
			List<MemoryMatch<SearchData>> scanResults = new ArrayList<>();
			for (MemoryMatch<SearchData> match : matches) {
				if (scanner.accept(match)) {
					scanResults.add(match);
				}
				if (monitor.isCancelled()) {
					break;
				}
			}

			MemoryMatch<SearchData> firstIfReduced = getFirstMatchIfReduced(matches, scanResults);
			tableModel.addInitialLoadListener(b -> tableLoadComplete(firstIfReduced));
			tableModel.setLoader(new RefreshResultsTableLoader(scanResults));
		}

		private MemoryMatch<SearchData> getFirstMatchIfReduced(
				List<MemoryMatch<SearchData>> matches,
				List<MemoryMatch<SearchData>> scanResults) {
			MemoryMatch<SearchData> firstIfReduced = null;
			if (!scanResults.isEmpty() && scanResults.size() != matches.size()) {
				firstIfReduced = scanResults.isEmpty() ? null : scanResults.getFirst();
			}
			return firstIfReduced;
		}
	}
}
