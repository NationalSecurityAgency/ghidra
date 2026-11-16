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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.builder.ActionBuilder;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.AbstractDebuggerPlugin;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.plugin.core.debug.gui.register.DebuggerRegisterActionContext;
import ghidra.app.plugin.core.debug.gui.register.RegisterRow;
import ghidra.app.plugin.core.debug.gui.watch.DebuggerWatchActionContext;
import ghidra.app.services.*;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.debug.api.watch.WatchRow;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.listing.TraceCodeUnit;
import ghidra.trace.model.listing.TraceData;
import ghidra.trace.model.memory.TraceMemorySpace;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.task.*;

@PluginInfo(
	shortDescription = "Backward and forward slice trace values",
	description = "Interactively explore dynamic and static slices of trace values",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.STABLE,
	servicesRequired = {
		DebuggerTraceManagerService.class,
		DebuggerStaticMappingService.class,
		DebuggerListingService.class },
	eventsConsumed = {
	})
public class DebuggerTraceSlicePlugin extends AbstractDebuggerPlugin {
	private List<AbstractSliceProvider> providers = new ArrayList<>();

	public DebuggerTraceSlicePlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		new ActionBuilder("Backward Slice", getName())
				.description("Open a backward slice for the current trace code unit")
				.popupMenuPath("Slice", "Backward")
				.enabledWhen(this::enabledSlice)
				.onAction(this::openBackwardSlice)
				.buildAndInstall(tool);
		new ActionBuilder("Forward Slice", getName())
				.description("Open a forward slice for the current trace code unit")
				.popupMenuPath("Slice", "Forward")
				.enabledWhen(this::enabledSlice)
				.onAction(this::openForwardSlice)
				.buildAndInstall(tool);
		new ActionBuilder("Load Slice Session", getName())
				.description("Load a saved slicing session")
				.menuPath(DebuggerPluginPackage.NAME, "Load Slice Session...")
				.menuGroup("Slicing")
				.menuIcon(DebuggerResources.ICON_IMPORT)
				.onAction(ctx -> loadSession(ctx))
				.buildAndInstall(tool);
	}

	@Override
	protected void dispose() {
		for (AbstractSliceProvider provider : List.copyOf(providers)) {
			tool.removeComponentProvider(provider);
			provider.dispose();
		}
		super.dispose();
	}

	record WhereUnit(CodeUnit unit, Trace trace, long snap) {}

	private WhereUnit unitFromContext(ActionContext ctx) {
		return switch (ctx) {
			case ProgramLocationActionContext plac -> unitFromLocationContext(plac);
			case DebuggerRegisterActionContext drac -> unitFromRegisterContext(drac);
			case DebuggerWatchActionContext dwac -> unitFromWatchContext(dwac);
			case DebuggerSnapActionContext dsac -> unitFromSnapContext(dsac);
			case SliceActionContext sac -> unitFromSliceContext(sac);
			default -> null;
		};
	}

	private WhereUnit unitFromLocationContext(ProgramLocationActionContext ctx) {
		ProgramLocation loc = ctx.getLocation();
		Program program = loc.getProgram();
		if (program instanceof TraceProgramView view) {
			long snap = view.getSnap();
			// TODO: Sort out how this work with scratch snaps
			Trace trace = view.getTrace();
			TraceCodeUnit unit =
				trace.getCodeManager().codeUnits().getContaining(snap, loc.getByteAddress());
			if (loc.getComponentPath() != null && unit instanceof TraceData data) {
				unit = data.getComponent(loc.getComponentPath());
			}
			return new WhereUnit(unit, trace, snap);
		}
		// Take the static unit as a cue for what to impose in the dynamic.
		DebuggerStaticMappingService ms = tool.getService(DebuggerStaticMappingService.class);
		if (ms == null) {
			return null;
		}
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		if (traceManager == null) {
			return null;
		}

		Trace trace = traceManager.getCurrentTrace();
		if (trace == null) {
			return null;
		}
		long snap = traceManager.getCurrentSnap();

		CodeUnit stUnit = program.getListing().getCodeUnitContaining(loc.getByteAddress());
		if (loc.getComponentPath() != null && stUnit instanceof Data stData) {
			stUnit = stData.getComponent(loc.getComponentPath());
		}

		TraceLocation tloc = ms.getOpenMappedLocation(trace,
			new ProgramLocation(program, stUnit.getAddress()), snap);
		if (tloc == null) {
			return null;
		}

		Address min = tloc.getAddress();
		CodeUnit dyUnit = switch (stUnit) {
			case Data _ -> SliceAnalysis.INSTANCE.getOrPseudoData(trace, snap,
				new AddressRangeImpl(min, min.add(stUnit.getLength() - 1)));
			case Instruction stIns -> SliceAnalysis.INSTANCE.getOrDisassemble(trace, snap, min,
				stIns.getRegisterValue(trace.getBaseLanguage().getContextBaseRegister()));
			default -> throw new AssertionError();
		};
		return new WhereUnit(dyUnit, trace, snap);
	}

	private AddressRange checkForRegRange(AddressRange range, DebuggerCoordinates coords) {
		if (range == null) {
			return null;
		}
		Trace trace = coords.getTrace();
		if (range.getAddressSpace().isRegisterSpace()) {
			TraceThread thread = coords.getThread();
			if (thread == null) {
				return null;
			}
			TraceMemorySpace regs = trace.getMemoryManager().getMemoryRegisterSpace(thread, false);
			if (regs == null) {
				return null;
			}
			AddressSpace space = regs.getAddressSpace();
			return new AddressRangeImpl(
				space.getOverlayAddress(range.getMinAddress()),
				space.getOverlayAddress(range.getMaxAddress()));
		}
		else if (range.getAddressSpace().isMemorySpace()) {
			return range;
		}
		return null; // No uniques or other spaces
	}

	private WhereUnit unitFromRegisterContext(DebuggerRegisterActionContext ctx) {
		RegisterRow selected = ctx.getSelected();
		Register register = selected.getRegister();
		DebuggerCoordinates coords = selected.getCurrent();
		AddressRange range =
			checkForRegRange(TraceRegisterUtils.rangeForRegister(register), coords);
		if (range == null) {
			return null;
		}
		Data data =
			SliceAnalysis.INSTANCE.getOrPseudoData(coords.getTrace(), coords.getSnap(), range);
		return new WhereUnit(data, coords.getTrace(), coords.getSnap());
	}

	private WhereUnit unitFromWatchContext(DebuggerWatchActionContext ctx) {
		WatchRow watch = ctx.getWatchRow();
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		if (traceManager == null) {
			return null;
		}
		DebuggerCoordinates coords = traceManager.getCurrent();
		Trace trace = coords.getTrace();
		if (trace == null) {
			return null;
		}
		AddressRange range = checkForRegRange(watch.getRange(), coords);
		if (range == null) {
			return null;
		}
		long snap = coords.getSnap();
		Data data = SliceAnalysis.INSTANCE.getOrPseudoData(trace, snap, range);
		return new WhereUnit(data, trace, snap);
	}

	private WhereUnit unitFromSnapContext(DebuggerSnapActionContext ctx) {
		Trace trace = ctx.getTrace();
		if (trace == null) {
			return null;
		}
		long snap = ctx.getSnap();
		Instruction instruction = SliceAnalysis.INSTANCE.getInstructionAtPc(trace, snap);
		if (instruction == null) {
			return null;
		}
		return new WhereUnit(instruction, trace, snap);
	}

	private WhereUnit unitFromSliceContext(SliceActionContext ctx) {
		List<AbstractSliceNode> selection = ctx.getSelection();
		if (selection.size() != 1) {
			return null;
		}
		if (!(selection.getFirst() instanceof UnitSliceNode<?> node)) {
			return null;
		}
		return new WhereUnit(node.unit, node.trace, node.snap);
	}

	private boolean enabledSlice(ActionContext ctx) {
		return unitFromContext(ctx) != null;
	}

	private void openBackwardSlice(ActionContext ctx) {
		WhereUnit wu = unitFromContext(ctx);
		if (wu != null) {
			BackwardSliceProvider provider =
				new BackwardSliceProvider(this, wu.trace(), wu.unit(), wu.snap());
			providers.add(provider);
			provider.show();
		}
	}

	private void openForwardSlice(ActionContext ctx) {
		WhereUnit wu = unitFromContext(ctx);
		if (wu != null) {
			ForwardSliceProvider provider =
				new ForwardSliceProvider(this, wu.trace(), wu.unit(), wu.snap());
			providers.add(provider);
			provider.show();
		}
	}

	void saveSession(AbstractSliceProvider provider) {
		File file = chooseSessionFile(provider.getComponent(), "Save Slice Session", "Save", true);
		if (file == null) {
			return;
		}
		SliceSession.Session session = new SliceSession.Session();
		session.trace = provider.getTrace().getName();
		session.direction = provider.getDirection();
		session.nodes.addAll(provider.saveNodes());
		try {
			Files.writeString(file.toPath(), SliceSession.write(session));
		}
		catch (IOException e) {
			Msg.showError(this, provider.getComponent(), "Save Slice Session",
				"Could not save slice session", e);
		}
	}

	private void loadSession(ActionContext ctx) {
		File file =
			chooseSessionFile(ctx.getSourceComponent(), "Load Slice Session", "Load", false);
		if (file == null) {
			return;
		}
		class LoadTask extends Task {
			SliceSession.Session session;
			Trace trace;
			List<AbstractSliceNode> restoredNodes;

			LoadTask() {
				super("Load Slice Session", true, true, false);
			}

			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					monitor.setMessage("Restoring slice session");
					session = SliceSession.read(Files.readString(file.toPath()));
					trace = tool.getService(DebuggerTraceManagerService.class)
							.getOpenTraces()
							.stream()
							.filter(t -> t.getName().equals(session.trace))
							.findFirst()
							.orElseThrow(
								() -> new IOException("Trace is not open: " + session.trace));
					/**
					 * HACK: A fake root from which top-level nodes are derived. The provider will
					 * create the actual root, but we shouldn't make a provider until we've
					 * succeeded in restoring the nodes
					 */
					RootSliceNode root = new RootSliceNode(trace, null, null);
					restoredNodes = new ArrayList<>();
					monitor.initialize(session.totalSize());
					for (SliceSession.Node saved : session.nodes) {
						monitor.checkCancelled();
						restoredNodes
								.add(SliceSession.restoreNode(root, trace, saved, tool, monitor));
					}
				}
				catch (IOException e) {
					Msg.showError(DebuggerTraceSlicePlugin.this, ctx.getSourceComponent(),
						"Load Slice Session", "Could not load slice session", e);
				}
			}
		}
		LoadTask task = new LoadTask();
		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCompleted(Task completedTask) {
				if (!tool.getService(DebuggerTraceManagerService.class)
						.getOpenTraces()
						.contains(task.trace)) {
					// Trace was closed while loading the slice session
					return;
				}
				AbstractSliceProvider provider = switch (task.session.direction) {
					case BACKWARD -> new BackwardSliceProvider(DebuggerTraceSlicePlugin.this,
						task.trace);
					case FORWARD -> new ForwardSliceProvider(DebuggerTraceSlicePlugin.this,
						task.trace);
				};
				provider.addRestoredNodes(task.restoredNodes);
				providers.add(provider);
				provider.show();
			}

			@Override
			public void taskCancelled(Task cancelledTask) {
				// Do not publish a partial session.
			}
		});
		new TaskLauncher(task);
	}

	private File chooseSessionFile(java.awt.Component parent, String title, String approveText,
			boolean save) {
		GhidraFileChooser chooser = new GhidraFileChooser(parent);
		chooser.setTitle(title);
		chooser.setApproveButtonText(approveText);
		chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		chooser.setSelectedFileFilter(GhidraFileFilter.ALL);
		chooser.setFileFilter(new ExtensionFileFilter("json", "JSON Slice Session"));
		File file = chooser.getSelectedFile();
		chooser.dispose();
		if (file == null) {
			return null;
		}
		if (!file.getName().toLowerCase().endsWith(".json")) {
			file = new File(file.getParentFile(), file.getName() + ".json");
		}
		if (save && file.exists()) {
			int result = OptionDialog.showYesNoCancelDialog(parent, "Overwrite Confirmation",
				"Overwrite slice session file?\n" + file);
			if (result != OptionDialog.YES_OPTION) {
				return null;
			}
		}
		return file;
	}
}
