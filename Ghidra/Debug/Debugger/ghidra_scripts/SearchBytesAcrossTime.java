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
// Search the entire trace, across all time, for a user-specified byte pattern.
//@category Debugger  

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import docking.ComponentProvider;
import docking.widgets.table.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.DebuggerListingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncUtils;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.trace.model.*;
import ghidra.trace.model.memory.TraceMemoryManager;

public class SearchBytesAcrossTime extends GhidraScript {
	public record Row(Address address, long startSnap, long endSnap) {
		Row(TraceAddressSnapRange match) {
			this(match.getRange().getMinAddress(), match.getLifespan().lmin(),
					match.getLifespan().lmax());
		}
	}

	private static class ResultsProvider extends ComponentProvider {
		private final JComponent component;

		ResultsProvider(PluginTool tool, String title, List<Row> rows) {
			super(tool, title, ResultsProvider.class.getSimpleName());

			AnyObjectTableModel<Row> model =
					new AnyObjectTableModel<>("Matches", Row.class, "startSnap", "endSnap",
							"address");
			model.setModelData(rows);
			GTable table = new GTable(model);

			table.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					if (e.getClickCount() != 2) {
						return;
					}
					int viewRow = table.getSelectedRow();
					if (viewRow == -1) {
						return;
					}
					int modelRow = table.convertRowIndexToModel(viewRow);
					Row row = rows.get(modelRow);
					navigateTo(tool, row.startSnap, row.address);
				}
			});

			GTableFilterPanel<Row> filterPanel = new GTableFilterPanel<>(table, model);

			final JPanel panel = new JPanel(new BorderLayout());
			panel.add(new JScrollPane(table));
			panel.add(filterPanel, BorderLayout.SOUTH);

			component = panel;
			setTransient();
			setVisible(true);
		}

		private void navigateTo(PluginTool tool, long snap, Address address) {
			DebuggerTraceManagerService traceManager =
					tool.getService(DebuggerTraceManagerService.class);
			DebuggerListingService listingService = tool.getService(DebuggerListingService.class);

			DebuggerCoordinates coords = traceManager.getCurrent().snap(snap);

			traceManager.activateAndNotify(coords, ActivationCause.USER)
					.thenRunAsync(() -> listingService.goTo(address, true),
							AsyncUtils.SWING_EXECUTOR);
		}

		@Override
		public JComponent getComponent() {
			return component;
		}
	}

	@Override
	protected void run() throws Exception {
		DebuggerTraceManagerService traceManager =
				state.getTool().getService(DebuggerTraceManagerService.class);
		Trace trace = traceManager.getCurrentTrace();
		if (trace == null) {
			printerr("No trace is active");
			return;
		}

		byte[] pattern = askBytes("Search Across Time", "Enter byte pattern to search for:");
		if (pattern == null || pattern.length == 0) {
			printerr("No pattern given");
			return;
		}

		TraceMemoryManager mem = trace.getMemoryManager();

		List<Row> rows = new ArrayList<>();

		// This searches the default address space, if your architecture uses other address spaces
		// this needs to be updated.
		AddressRange fullRange = new AddressRangeImpl(toAddr(0L), toAddr(0xFFFF_FFFF_FFFF_FFFFL));
		List<TraceAddressSnapRange> bytesAcrossLifespan =
				mem.findBytesAcrossLifespan(Lifespan.ALL, fullRange, pattern, monitor);

		for (TraceAddressSnapRange traceAddressSnapRange : bytesAcrossLifespan) {
			rows.add(new Row(traceAddressSnapRange));
		}
		
		println("Found " + rows.size() + " match(es)");
		new ResultsProvider(state.getTool(), "Search Across Time Results MEMORY_BLOCKS", rows);
	}
}
