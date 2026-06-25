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
package ghidra.app.plugin.core.debug.gui.breakpoint.timeline;

import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;

import docking.*;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.table.AnyObjectTableModel;
import docking.widgets.table.GTable;
import ghidra.app.plugin.core.byteviewer.ByteViewerActionContext;
import ghidra.app.plugin.core.codebrowser.CodeViewerActionContext;
import ghidra.app.plugin.core.debug.gui.listing.DebuggerListingActionContext;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterActionContext;
import ghidra.app.services.DebuggerStaticMappingService;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.symbol.TraceReference;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.util.Msg;

public class BreakpointTimelineActions {
	private enum BreakType {
		EXECUTE("Execution"), READ("Memory Read"), WRITE("Memory Write"), ACCESS("Memory Access");

		final String menuName;

		BreakType(String menuName) {
			this.menuName = menuName;
		}

		String infoTitle() {
			return switch (this) {
				case EXECUTE -> "Execute search";
				case READ -> "Read search";
				case WRITE -> "Write search";
				case ACCESS -> "Access search";
			};
		}

		String plural() {
			return switch (this) {
				case EXECUTE -> "executions";
				case READ -> "memory reads";
				case WRITE -> "memory writes";
				case ACCESS -> "memory accesses";
			};
		}
	}

	private enum SearchType {
		FIRST("First...", "Go To First"),
		PREVIOUS("Previous...", "Go To Previous"),
		NEXT("Next." + "..", "Go To Next"),
		FINAL("Final...", "Go To Final"),
		ALL("Show All...", "Show All");

		final String menuGroup;
		final String actionName;

		SearchType(String menuGroup, String actionName) {
			this.menuGroup = menuGroup;
			this.actionName = actionName;
		}
	}

	protected record AddressSnap(Address address, Long snap) {
	}

	private class BreakpointTimelineActionProvider extends ComponentProvider {
		private final JComponent component;
		private final List<AddressSnap> snaps;

		public BreakpointTimelineActionProvider(Tool tool, String title,
				List<AddressSnap> snapList) {
			super(tool, title, BreakpointTimelineActions.this.name);
			snaps = new ArrayList<>(snapList);

			final AnyObjectTableModel<AddressSnap> model =
					new AnyObjectTableModel<>("AddressSnap", AddressSnap.class, "snap", "address");
			model.setModelData(snaps);
			final GTable table = new GTable(model);

			table.addMouseListener(new MouseAdapter() {
				@Override
				public void mouseClicked(MouseEvent e) {
					if (e.getClickCount() == 2) {
						final int row = table.getSelectedRow();
						if (row != -1) {
							tool.getService(DebuggerTraceManagerService.class)
									.activateSnap(snaps.get(row).snap());
						}
					}
				}
			});

			component = new JScrollPane(table);
			setTransient();
			setVisible(true);
		}

		@Override
		public JComponent getComponent() {
			return component;
		}

	}

	private class TimelineAction extends DockingAction {
		private final BreakType breakType;
		private final SearchType searchType;
		private final PluginTool tool;

		private TimelineAction(PluginTool tool, SearchType searchType, BreakType breakType) {
			super(searchType.actionName + " " + breakType.menuName,
					BreakpointTimelineActions.this.name);
			this.breakType = breakType;
			this.tool = tool;
			this.searchType = searchType;

			if (searchType != SearchType.ALL) {
				setPopupMenuData(new MenuData(
						new String[] { "Go to...", searchType.menuGroup, breakType.menuName },
						null,
						BreakpointTimelineActions.this.name));
			}
			else {
				setPopupMenuData(
						new MenuData(new String[] { searchType.menuGroup, breakType.menuName },
								null, BreakpointTimelineActions.this.name));
			}
		}

		@Override
		public void actionPerformed(ActionContext context) {
			final AddressSet addrRange = getAddessRangeFromContext(context);
			final Lifespan lifespan = getLifespan();
			final Trace currentTrace =
					tool.getService(DebuggerTraceManagerService.class).getCurrentTrace();

			if (addrRange == null) {
				return;
			}

			switch (breakType) {
				case EXECUTE -> handleExecutionAction(addrRange, lifespan, currentTrace);
				case READ, WRITE, ACCESS -> handleMemoryAction(addrRange, lifespan, currentTrace);
			}
		}

		private AddressSet getAddessRangeFromContext(ActionContext context) {
			return switch (context) {
				case final CodeViewerActionContext c ->
						getAddressRangeFromCodeViewerActionContext(c);
				case final DebuggerListingActionContext c ->
						getAddressRangeFromDebuggerListingActionContext(c);
				case final DebuggerRegisterActionContext c ->
						getAddressRangeFromDebuggerRegisterActionContext(c);
				case final ByteViewerActionContext c ->
						getAddressRangeFromByteViewerActionContext(c);
				default -> null;
			};
		}

		private Lifespan getLifespan() {
			final long currentSnap =
					tool.getService(DebuggerTraceManagerService.class).getCurrentSnap();
			return switch (searchType) {
				case ALL, FINAL, FIRST -> Lifespan.ALL;
				case NEXT -> Lifespan.nowOn(currentSnap + 1);
				case PREVIOUS -> Lifespan.before(currentSnap);
			};
		}

		private void handleExecutionAction(AddressSet addrSet, Lifespan lifespan,
				Trace currentTrace) {
			final List<? extends TraceObjectValue> hits = currentTrace.getObjectManager()
					.getRootSchema()
					.getContext()
					.getAllSchemas()
					.stream()
					.filter(e -> e.getInterfaces().contains(TraceStackFrame.class))
					.map(s -> s.checkAliasedAttribute(TraceStackFrame.KEY_PC))
					.flatMap(e -> addrSet.stream()
							.flatMap(addrRange -> currentTrace.getObjectManager()
									.getValuesIntersecting(lifespan, addrRange, e)
									.stream()))
					.sorted(Comparator.comparingLong(TraceObjectValue::getMinSnap))
					.toList();

			if (!hits.isEmpty()) {
				if (searchType == SearchType.ALL) {
					new BreakpointTimelineActionProvider(tool,
							"All executions in %s - %s".formatted(addrSet.getMinAddress(),
									addrSet.getMaxAddress()), hits.stream()
							.map(c -> new AddressSnap(c.castValue(), c.getMinSnap()))
							.toList());
					return;
				}
				final Long snap = switch (searchType) {
					case FINAL, PREVIOUS -> hits.getLast().getMinSnap();
					case FIRST, NEXT -> hits.getFirst().getMinSnap();
					default -> null;
				};
				if (snap == null) {
					return;
				}
				tool.getService(DebuggerTraceManagerService.class).activateSnap(snap);
			}
			else if (searchType == SearchType.ALL) {
				Msg.showInfo(this, null, breakType.infoTitle(),
						"There are no executions at this location");
			}
			else {
				Msg.showInfo(this, null, breakType.infoTitle(),
						"There is no %s execution at this location".formatted(
								searchType.name().toLowerCase()));
			}
		}

		private void handleMemoryAction(AddressSet addrSet, Lifespan lifespan,
				Trace currentTrace) {
			final List<? extends TraceReference> hits = addrSet.stream()
					.flatMap(addrRange -> currentTrace.getReferenceManager()
							.getReferencesToRange(lifespan, addrRange)
							.stream())
					.sorted(Comparator.comparingLong(TraceReference::getStartSnap))
					.toList();

			if (!hits.isEmpty()) {
				if (searchType == SearchType.ALL) {
					new BreakpointTimelineActionProvider(tool,
							"All %s in %s - %s".formatted(breakType.name(),
									addrSet.getMinAddress(),
									addrSet.getMaxAddress()), hits.stream()
							.map(c -> new AddressSnap(c.getFromAddress(), c.getStartSnap()))
							.toList());
					return;
				}
				final Long snap = switch (searchType) {
					case FINAL, PREVIOUS -> hits.getLast().getStartSnap();
					case FIRST, NEXT -> hits.getFirst().getStartSnap();
					default -> null;
				};
				if (snap == null) {
					return;
				}
				tool.getService(DebuggerTraceManagerService.class).activateSnap(snap);
			}
			else if (searchType == SearchType.ALL) {
				Msg.showInfo(this, null, breakType.infoTitle(),
						"There are no %s to this location".formatted(breakType.plural()));
			}
			else {
				Msg.showInfo(this, null, breakType.infoTitle(),
						"There is no %s %s to this location".formatted(
								searchType.name().toLowerCase(),
								breakType.menuName.toLowerCase()));
			}
		}

		private AddressSet getAddressRangeFromCodeViewerActionContext(CodeViewerActionContext c) {
			final Trace trace =
					tool.getService(DebuggerTraceManagerService.class).getCurrentTrace();
			final DebuggerStaticMappingService staticMappingService =
					tool.getService(DebuggerStaticMappingService.class);
			final AddressSet dynamicSet = new AddressSet();
			String noMapping = "No mapping";
			String noMappingFormat = "No mapping for %s @ 0x%x";

			if (c.getSelection().isEmpty()) {
				final ProgramLocation dynamicLocation =
						staticMappingService.getDynamicLocationFromStatic(trace.getProgramView(),
								new ProgramLocation(c.getProgram(), c.getAddress()));
				if (dynamicLocation == null) {
					Msg.showInfo(null, null, noMapping,
							noMappingFormat.formatted(c.getProgram(), c.getAddress().getOffset()));
				}
				else {
					dynamicSet.add(dynamicLocation.getAddress());
				}
			}
			else {
				for (final AddressRange range : c.getSelection().getAddressRanges()) {
					final ProgramLocation startDynamicLocation =
							staticMappingService.getDynamicLocationFromStatic(
									trace.getProgramView(),
									new ProgramLocation(c.getProgram(), range.getMinAddress()));
					if (startDynamicLocation == null) {
						Msg.showInfo(null, null, noMapping,
								noMappingFormat.formatted(c.getProgram(),
										range.getMinAddress().getOffset()));
						continue;
					}
					final ProgramLocation endDynamicLocation =
							staticMappingService.getDynamicLocationFromStatic(
									trace.getProgramView(),
									new ProgramLocation(c.getProgram(), range.getMaxAddress()));
					if (endDynamicLocation == null) {
						Msg.showInfo(null, null, noMapping,
								noMappingFormat.formatted(c.getProgram(),
										range.getMaxAddress().getOffset()));
						continue;
					}
					dynamicSet.add(startDynamicLocation.getAddress(),
							endDynamicLocation.getAddress());
				}
			}
			return dynamicSet;
		}

		private AddressSet getAddressRangeFromDebuggerListingActionContext(
				DebuggerListingActionContext c) {
			final AddressSet dynamicSet = new AddressSet();
			if (c.getSelection().isEmpty()) {
				dynamicSet.add(c.getAddress());
			}
			else {
				for (final AddressRange range : c.getSelection().getAddressRanges()) {
					dynamicSet.add(range.getMinAddress(), range.getMaxAddress());
				}
			}
			return dynamicSet;
		}

		private AddressSet getAddressRangeFromDebuggerRegisterActionContext(
				DebuggerRegisterActionContext c) {
			final AddressSpace addressSpace = tool.getService(DebuggerTraceManagerService.class)
					.getCurrentTrace()
					.getProgramView()
					.getAddressFactory()
					.getDefaultAddressSpace();
			final long regValue = c.getSelected().getValue().longValue();
			final Address addr = addressSpace.getAddress(regValue);
			final AddressSet addressSet = new AddressSet();
			addressSet.add(addr);
			return addressSet;
		}

		private AddressSet getAddressRangeFromByteViewerActionContext(ByteViewerActionContext c) {
			final AddressSet dynamicSet = new AddressSet();

			for (final AddressRange range : c.getSelection().getAddressRanges()) {
				dynamicSet.add(range.getMinAddress(), range.getMaxAddress());
			}
			return dynamicSet;
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			return ((context instanceof CodeViewerActionContext) ||
					        (context instanceof DebuggerListingActionContext) ||
					        (context instanceof DebuggerRegisterActionContext) ||
					        (context instanceof ByteViewerActionContext));
		}
	}

	private final PluginTool tool;
	String name = this.getClass().getSimpleName();
	List<TimelineAction> actions;

	BreakpointTimelineActions(PluginTool tool) {
		this.tool = tool;
		actions = new ArrayList<>();
		for (final SearchType searchType : SearchType.values()) {
			for (final BreakType breakType : BreakType.values()) {
				final TimelineAction action = new TimelineAction(tool, searchType, breakType);
				tool.addAction(action);
			}
		}
	}

	void dispose() {
		for (final TimelineAction action : actions) {
			tool.removeAction(action);
		}
	}
}
