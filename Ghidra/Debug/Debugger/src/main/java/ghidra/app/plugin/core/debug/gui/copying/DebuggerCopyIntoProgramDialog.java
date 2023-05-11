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
package ghidra.app.plugin.core.debug.gui.copying;

import java.awt.*;
import java.io.IOException;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.function.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import db.Transaction;
import docking.ReusableDialogComponentProvider;
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.copying.DebuggerCopyPlan.Copier;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerStaticMappingService.MappedAddressRange;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryRegion;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.task.*;

public class DebuggerCopyIntoProgramDialog extends ReusableDialogComponentProvider {
	static final int GAP = 5;
	static final int BUTTON_SIZE = 32;

	protected static class RangeEntry {
		private final String regionName;
		private final String moduleNames;
		private final String sectionNames;
		private final AddressRange srcRange;
		private String blockName;
		private final boolean create;
		private final boolean overlay;
		private final AddressRange dstRange;

		protected RangeEntry(String regionName, String moduleNames, String sectionNames,
				AddressRange srcRange, String blockName, boolean create, boolean overlay,
				AddressRange dstRange) {
			this.regionName = regionName;
			this.moduleNames = moduleNames;
			this.sectionNames = sectionNames;
			this.srcRange = srcRange;
			this.blockName = blockName;
			this.create = create;
			this.overlay = overlay;
			this.dstRange = dstRange;
		}

		public String getRegionName() {
			return regionName;
		}

		public String getModuleNames() {
			return moduleNames;
		}

		public String getSectionNames() {
			return sectionNames;
		}

		public AddressRange getSrcRange() {
			return srcRange;
		}

		public Address getSrcMinAddress() {
			return srcRange.getMinAddress();
		}

		public Address getSrcMaxAddress() {
			return srcRange.getMaxAddress();
		}

		public AddressRange getDstRange() {
			return dstRange;
		}

		public String getBlockName() {
			return create ? blockName : (blockName + " *");
		}

		public void setBlockName(String blockName) {
			if (!create) {
				throw new IllegalStateException("Cannot modify name of existing block");
			}
			this.blockName = blockName;
		}

		public boolean isCreate() {
			return create;
		}

		public boolean isOverlay() {
			return overlay;
		}

		public Address getDstMinAddress() {
			return dstRange.getMinAddress();
		}

		public Address getDstMaxAddress() {
			return dstRange.getMaxAddress();
		}
	}

	protected enum RangeTableColumns
		implements EnumeratedTableColumn<RangeTableColumns, RangeEntry> {
		REMOVE("Remove", String.class, e -> "Remove Range", (e, v) -> nop(), null),
		REGION("Region", String.class, RangeEntry::getRegionName),
		MODULES("Modules", String.class, RangeEntry::getModuleNames),
		SECTIONS("Sections", String.class, RangeEntry::getSectionNames),
		SRC_MIN("SrcMin", Address.class, RangeEntry::getSrcMinAddress),
		SRC_MAX("SrcMax", Address.class, RangeEntry::getSrcMaxAddress),
		BLOCK("Block", String.class, RangeEntry::getBlockName, RangeEntry::setBlockName, //
				RangeEntry::isCreate),
		OVERLAY("Overlay", Boolean.class, RangeEntry::isOverlay),
		DST_MIN("DstMin", Address.class, RangeEntry::getDstMinAddress),
		DST_MAX("DstMax", Address.class, RangeEntry::getDstMaxAddress);

		private static void nop() {
		}

		private final String header;
		private final Class<?> cls;
		private final Function<RangeEntry, ?> getter;
		private final BiConsumer<RangeEntry, Object> setter;
		private final Predicate<RangeEntry> editable;

		@SuppressWarnings("unchecked")
		<T> RangeTableColumns(String header, Class<T> cls, Function<RangeEntry, T> getter,
				BiConsumer<RangeEntry, T> setter, Predicate<RangeEntry> editable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<RangeEntry, Object>) setter;
			this.editable = editable;
		}

		<T> RangeTableColumns(String header, Class<T> cls, Function<RangeEntry, T> getter) {
			this(header, cls, getter, null, null);
		}

		@Override
		public String getHeader() {
			return header;
		}

		@Override
		public Class<?> getValueClass() {
			return cls;
		}

		@Override
		public Object getValueOf(RangeEntry row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(RangeEntry row) {
			return setter != null && (editable == null || editable.test(row));
		}

		@Override
		public void setValueOf(RangeEntry row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class RangeTableModel
			extends DefaultEnumeratedColumnTableModel<RangeTableColumns, RangeEntry> {
		public RangeTableModel(PluginTool tool) {
			super(tool, "Ranges", RangeTableColumns.class);
		}

		@Override
		public List<RangeTableColumns> defaultSortOrder() {
			return List.of(RangeTableColumns.SRC_MIN);
		}
	}

	protected interface CopyDestination {
		default Program getExistingProgram() {
			return null;
		}

		default boolean isExisting() {
			return getExistingProgram() != null;
		}

		Program getOrCreateProgram(TraceProgramView source, Object consumer) throws IOException;

		default void saveIfApplicable(Program program) {
		}
	}

	protected static final CopyDestination TEMP_PROGRAM = new CopyDestination() {
		@Override
		public String toString() {
			return "<Temporary Program>";
		}

		@Override
		public Program getOrCreateProgram(TraceProgramView source, Object consumer)
				throws IOException {
			return new ProgramDB(source.getName(), source.getLanguage(), source.getCompilerSpec(),
				consumer);
		}
	};

	protected final CopyDestination NEW_PROGRAM = new CopyDestination() {
		@Override
		public String toString() {
			return "<New Program>";
		}

		@Override
		public Program getOrCreateProgram(TraceProgramView source, Object consumer)
				throws IOException {
			return new ProgramDB(source.getName(), source.getLanguage(), source.getCompilerSpec(),
				consumer);
		}

		@Override
		public void saveIfApplicable(Program program) {
			programManager.saveProgramAs(program);
		}
	};

	protected static class OpenProgramDestination implements CopyDestination {
		private final Program program;

		public OpenProgramDestination(Program program) {
			this.program = program;
		}

		@Override
		public String toString() {
			return program.getName();
		}

		@Override
		public Program getExistingProgram() {
			return program;
		}

		@Override
		public Program getOrCreateProgram(TraceProgramView source, Object consumer) {
			return program;
		}
	}

	protected DebuggerModelService modelService;
	protected ProgramManager programManager;
	protected DebuggerStaticMappingService staticMappingService;

	protected TraceProgramView source;
	protected AddressSetView set;

	protected CompletableFuture<Void> lastTask;
	protected CompletableFuture<?> captureTask;

	protected final DefaultComboBoxModel<CopyDestination> comboDestinationModel =
		new DefaultComboBoxModel<>();
	protected JComboBox<CopyDestination> comboDestination;
	protected final Map<Program, CopyDestination> programDestinations = new HashMap<>();

	// TODO: Save these options to tool state?
	protected JCheckBox cbCapture;
	protected JCheckBox cbRelocate;
	protected JCheckBox cbUseOverlays;
	protected DebuggerCopyPlan plan = new DebuggerCopyPlan();

	protected final RangeTableModel tableModel;
	protected GTable table;
	protected GhidraTableFilterPanel<RangeEntry> filterPanel;

	protected JButton resetButton;

	public DebuggerCopyIntoProgramDialog(PluginTool tool) {
		super("Copy Into Program", true, true, true, true);

		tableModel = new RangeTableModel(tool);
		populateComponents();
	}

	protected void populateComponents() {
		plan.selectAll();
		JPanel panel = new JPanel(new BorderLayout());

		{
			JPanel opts = new JPanel();
			opts.setLayout(new BoxLayout(opts, BoxLayout.Y_AXIS));

			{
				Box progBox = Box.createHorizontalBox();
				progBox.setBorder(BorderFactory.createEmptyBorder(GAP, GAP, GAP, GAP));
				progBox.add(new JLabel("Destination:"));
				comboDestination = new JComboBox<>(comboDestinationModel);
				comboDestination.setBorder(BorderFactory.createEmptyBorder(0, GAP, 0, 0));
				comboDestination.addActionListener(e -> {
					if (!isVisible()) {
						return;
					}
					syncCbRelocateEnabled(getDestination());
					reset();
				});
				progBox.add(comboDestination);
				opts.add(progBox);
			}

			{
				// Avoid Swing's automatic indentation
				JPanel inner = new JPanel(new BorderLayout());
				inner.setBorder(BorderFactory.createEmptyBorder(0, GAP, GAP, GAP));
				cbCapture =
					new JCheckBox("<html>Read live target's memory");
				cbCapture.addActionListener(e -> {
					if (!isVisible()) {
						return;
					}
					reset();
				});
				inner.add(cbCapture);
				opts.add(inner);
			}

			{
				// Avoid Swing's automatic indentation
				JPanel inner = new JPanel(new BorderLayout());
				inner.setBorder(BorderFactory.createEmptyBorder(0, GAP, GAP, GAP));
				cbRelocate =
					new JCheckBox("<html>Relocate via Mappings. <b>WARNING:</b> No fixups");
				cbRelocate.addActionListener(e -> {
					if (!isVisible()) {
						return;
					}
					reset();
				});
				inner.add(cbRelocate);
				opts.add(inner);
			}

			{
				// No swing indentation
				JPanel inner = new JPanel(new BorderLayout());
				inner.setBorder(BorderFactory.createEmptyBorder(0, GAP, GAP, GAP));
				cbUseOverlays = new JCheckBox("<html>Use overlays where blocks already exist");
				cbUseOverlays.addActionListener(e -> {
					if (!isVisible()) {
						return;
					}
					reset();
				});
				inner.add(cbUseOverlays);
				opts.add(inner);
			}

			{
				JPanel panelInclude = new JPanel(new GridLayout(0, 2, GAP, GAP));
				panelInclude.setBorder(BorderFactory.createTitledBorder("Include:"));
				JButton buttonSelectNone = new JButton("Select None");
				buttonSelectNone.addActionListener(e -> plan.selectNone());
				panelInclude.add(buttonSelectNone);
				JButton buttonSelectAll = new JButton("Select All");
				buttonSelectAll.addActionListener(e -> plan.selectAll());
				panelInclude.add(buttonSelectAll);
				for (Copier copier : plan.getAllCopiers()) {
					panelInclude.add(plan.getCheckBox(copier));
				}
				opts.add(panelInclude);
			}
			panel.add(opts, BorderLayout.NORTH);
		}

		{
			JPanel tablePanel = new JPanel(new BorderLayout());
			table = new GTable(tableModel);
			table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
			tablePanel.add(new JScrollPane(table));
			filterPanel = new GhidraTableFilterPanel<>(table, tableModel);
			tablePanel.add(filterPanel, BorderLayout.SOUTH);
			panel.add(tablePanel, BorderLayout.CENTER);
		}

		panel.setMinimumSize(new Dimension(600, 600));
		addWorkPanel(panel);

		addOKButton();
		okButton.setText("Copy");
		addCancelButton();
		addResetButton();

		TableColumnModel columnModel = table.getColumnModel();

		TableColumn removeCol = columnModel.getColumn(RangeTableColumns.REMOVE.ordinal());
		CellEditorUtils.installButton(table, filterPanel, removeCol, DebuggerResources.ICON_DELETE,
			BUTTON_SIZE, this::removeEntry);
	}

	protected void addResetButton() {
		resetButton = new JButton("Reset");
		resetButton.setMnemonic('R');
		resetButton.setName("Reset");
		resetButton.addActionListener(e -> resetCallback());
		addButton(resetButton);
	}

	@Override
	protected void cancelCallback() {
		synchronized (this) {
			if (captureTask != null) {
				captureTask.cancel(false);
			}
		}
		super.cancelCallback();
	}

	@Override
	protected void okCallback() {
		super.okCallback();

		lastTask = new CompletableFuture<>();
		Task task = new Task("Copy Into Program", true, true, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				try {
					executePlan(monitor);
					Swing.runLater(() -> {
						setStatusText("");
						close();
					});
				}
				catch (Exception e) {
					Msg.error(this, "Error copying into program", e);
					setStatusText("Error: " + e.getMessage());
				}
			}
		};
		task.addTaskListener(new TaskListener() {
			@Override
			public void taskCancelled(Task task) {
				lastTask.cancel(false);
			}

			@Override
			public void taskCompleted(Task task) {
				lastTask.complete(null);
			}
		});
		executeProgressTask(task, 500);
	}

	protected void resetCallback() {
		reset();
	}

	protected void removeEntry(RangeEntry entry) {
		tableModel.delete(entry);
	}

	protected TraceRecorder getRecorderIfReadsPresent() {
		if (modelService == null) {
			return null;
		}
		TraceRecorder recorder = modelService.getRecorder(source.getTrace());
		if (recorder == null) {
			return null;
		}
		if (!DebuggerCoordinates.NOWHERE.view(source).recorder(recorder).isAliveAndReadsPresent()) {
			return null;
		}
		return recorder;
	}

	protected void checkCbCaptureEnabled() {
		boolean en = getRecorderIfReadsPresent() != null;
		cbCapture.setEnabled(en);
		cbCapture.setSelected(en);
	}

	public void setModelService(DebuggerModelService modelService) {
		this.modelService = modelService;
		checkCbCaptureEnabled();
	}

	public void setSource(TraceProgramView source, AddressSetView set) {
		this.source = source;
		this.set = set;
		checkCbCaptureEnabled();
	}

	public void setProgramManager(ProgramManager programManager) {
		this.programManager = programManager;
		setSelectablePrograms(programManager.getAllOpenPrograms());
	}

	protected void setSelectablePrograms(Program[] programs) {
		setSelectablePrograms(Arrays.asList(programs));
	}

	protected void setSelectablePrograms(Collection<Program> programs) {
		programDestinations.clear();
		comboDestinationModel.removeAllElements();
		comboDestinationModel.addElement(NEW_PROGRAM);
		comboDestinationModel.addElement(TEMP_PROGRAM);
		for (Program program : new LinkedHashSet<>(programs)) {
			OpenProgramDestination destination = new OpenProgramDestination(program);
			programDestinations.put(program, destination);
			comboDestinationModel.addElement(destination);
		}
	}

	public void setDestination(Program program) {
		setDestination(programDestinations.get(program));
	}

	protected void syncCbRelocateEnabled(CopyDestination dest) {
		cbRelocate.setEnabled(dest.getExistingProgram() != null);
	}

	public void setDestination(CopyDestination dest) {
		Objects.requireNonNull(dest);
		syncCbRelocateEnabled(dest);
		comboDestinationModel.setSelectedItem(dest);
	}

	public CopyDestination getDestination() {
		return (CopyDestination) comboDestinationModel.getSelectedItem();
	}

	public void setCapture(boolean capture) {
		if (capture && getRecorderIfReadsPresent() == null) {
			throw new IllegalStateException(
				"Cannot enable capture unless live and reading the present");
		}
		this.cbCapture.setSelected(capture);
	}

	public boolean isCapture() {
		return (cbCapture.isSelected() && getRecorderIfReadsPresent() != null);
	}

	public void setRelocate(boolean relocate) {
		if (relocate && !getDestination().isExisting()) {
			throw new IllegalStateException("Cannot relocate when creating a new program");
		}
		this.cbRelocate.setSelected(relocate);
	}

	public boolean isRelocate() {
		return cbRelocate.isSelected() && staticMappingService != null &&
			getDestination().isExisting();
	}

	public void setUseOverlays(boolean useOverlays) {
		if (useOverlays && !getDestination().isExisting()) {
			// Technically, you can, but why would you?
			throw new IllegalStateException("Cannot use overlays when creating a new program");
		}
		this.cbUseOverlays.setSelected(useOverlays);
	}

	public boolean isUseOverlays() {
		return cbUseOverlays.isSelected() && getDestination().isExisting();
	}

	public void setStaticMappingService(DebuggerStaticMappingService staticMappingService) {
		this.staticMappingService = staticMappingService;
		cbRelocate.setEnabled(staticMappingService != null);
	}

	/**
	 * Re-populate the table based on destination and relocation settings
	 */
	public void reset() {
		Program dest = getDestination().getExistingProgram();
		plan.syncCopiersEnabled(source, dest);
		if (isRelocate()) {
			resetWithRelocation(isUseOverlays(), dest);
		}
		else {
			resetWithoutRelocation(isUseOverlays(), dest);
		}
	}

	protected String createName(String desired, Set<String> taken) {
		if (taken.add(desired)) {
			return desired;
		}
		String candidate = desired;
		for (int i = 2;; i++) {
			candidate = desired + "_" + i;
			if (taken.add(candidate)) {
				return candidate;
			}
		}
	}

	protected String computeRegionString(AddressRange rng) {
		TraceMemoryManager mm = source.getTrace().getMemoryManager();
		Collection<? extends TraceMemoryRegion> regions =
			mm.getRegionsIntersecting(Lifespan.at(source.getSnap()), rng);
		return regions.isEmpty() ? "UNKNOWN" : regions.iterator().next().getName();
	}

	protected String computeModulesString(AddressRange rng) {
		TraceModuleManager mm = source.getTrace().getModuleManager();
		Collection<? extends TraceModule> modules =
			mm.getModulesIntersecting(Lifespan.at(source.getSnap()), rng);
		return modules.stream().map(m -> m.getName()).collect(Collectors.joining(","));
	}

	protected String computeSectionsString(AddressRange rng) {
		TraceModuleManager mm = source.getTrace().getModuleManager();
		Collection<? extends TraceSection> sections =
			mm.getSectionsIntersecting(Lifespan.at(source.getSnap()), rng);
		return sections.stream().map(s -> s.getName()).collect(Collectors.joining(","));
	}

	protected void createEntry(Collection<RangeEntry> result, AddressRange srcRange,
			AddressRange dstRange, boolean overlay, Set<String> taken, MemoryBlock dstBlock) {
		String srcName = computeRegionString(srcRange);
		String dstName = dstBlock != null ? dstBlock.getName() : createName(srcName, taken);
		String srcModules = computeModulesString(srcRange);
		String srcSections = computeSectionsString(srcRange);
		result.add(new RangeEntry(srcName, srcModules, srcSections, srcRange, dstName,
			dstBlock == null, overlay, dstRange));
	}

	protected void createEntries(Collection<RangeEntry> result, boolean useOverlays,
			MappedAddressRange mappedRng, AddressRange srcRange, AddressRange dstRange,
			Set<String> taken, Program dest) {
		if (dest == null) {
			createEntry(result, srcRange, dstRange, false, taken, null);
			return;
		}

		Memory memory = dest.getMemory();
		AddressSetView hits =
			memory.intersectRange(dstRange.getMinAddress(), dstRange.getMaxAddress());
		if (!hits.isEmpty() && useOverlays) {
			createEntry(result, srcRange, dstRange, true, taken, null);
			return;
		}

		AddressSetView misses = new AddressSet(dstRange).subtract(hits);
		for (AddressRange miss : misses) {
			createEntry(result, mappedRng.mapDestinationToSource(miss), miss, false, taken, null);
		}
		for (AddressRange hit : hits) {
			Address next = hit.getMinAddress();
			while (next != null && hit.contains(next)) {
				MemoryBlock block = memory.getBlock(next);
				AddressRange dr = hit.intersectRange(block.getStart(), block.getEnd());
				createEntry(result, mappedRng.mapDestinationToSource(dr), dr, false, taken, block);
				next = block.getEnd().next();
			}
		}
	}

	protected void collectBlockNames(Collection<String> result, Program program) {
		if (program == null) {
			return;
		}
		for (MemoryBlock b : program.getMemory().getBlocks()) {
			result.add(b.getName());
		}
	}

	protected List<AddressRange> breakRangeByRegions(AddressRange srcRange) {
		AddressSet remains = new AddressSet(srcRange);
		List<AddressRange> result = new ArrayList<>();
		for (TraceMemoryRegion region : source.getTrace()
				.getMemoryManager()
				.getRegionsIntersecting(Lifespan.at(source.getSnap()), srcRange)) {
			AddressRange range = region.getRange().intersect(srcRange);
			result.add(range);
			remains.delete(range);
		}
		remains.iterator().forEachRemaining(result::add);
		return result;
	}

	protected void resetWithRelocation(boolean useOverlays, Program dest) {
		Objects.requireNonNull(dest);
		tableModel.clear();
		List<RangeEntry> result = new ArrayList<>();
		Set<String> taken = new HashSet<>();
		collectBlockNames(taken, dest);
		Collection<MappedAddressRange> mappedSet = staticMappingService
				.getOpenMappedViews(source.getTrace(), set, source.getSnap())
				.get(dest);
		if (mappedSet == null) {
			return;
		}
		for (MappedAddressRange mappedRng : mappedSet) {
			for (AddressRange src : breakRangeByRegions(mappedRng.getSourceAddressRange())) {
				AddressRange dst = mappedRng.mapSourceToDestination(src);
				createEntries(result, useOverlays, mappedRng, src, dst, taken, dest);
			}
		}
		tableModel.addAll(result);
	}

	protected MappedAddressRange identityMapped(AddressRange srng, Program dest) {
		if (dest == null) { // New program
			return new MappedAddressRange(srng, srng);
		}
		AddressSpace srcSpace = srng.getAddressSpace();
		AddressSpace dstSpace = dest.getAddressFactory().getAddressSpace(srcSpace.getName());
		if (dstSpace == null) {
			return null;
		}
		long minOff = MathUtilities.unsignedMax(srng.getMinAddress().getOffset(),
			dstSpace.getMinAddress().getOffset());
		long maxOff = MathUtilities.unsignedMin(srng.getMaxAddress().getOffset(),
			dstSpace.getMaxAddress().getOffset());
		if (Long.compareUnsigned(minOff, maxOff) > 0) {
			return null;
		}
		return new MappedAddressRange(
			new AddressRangeImpl(srcSpace.getAddress(minOff), srcSpace.getAddress(maxOff)),
			new AddressRangeImpl(dstSpace.getAddress(minOff), dstSpace.getAddress(maxOff)));
	}

	protected void resetWithoutRelocation(boolean useOverlays, Program dest) {
		tableModel.clear();
		List<RangeEntry> result = new ArrayList<>();
		Set<String> taken = new HashSet<>();
		collectBlockNames(taken, dest);
		for (AddressRange rng : set) {
			for (AddressRange src : breakRangeByRegions(rng)) {
				MappedAddressRange id = identityMapped(src, dest);
				if (id == null) {
					continue;
				}
				createEntries(result, useOverlays, id, id.getSourceAddressRange(),
					id.getDestinationAddressRange(), taken, dest);
			}
		}
		tableModel.addAll(result);
	}

	protected MemoryBlock executeEntryBlock(RangeEntry entry, Program dest, TaskMonitor monitor)
			throws Exception {
		if (entry.isCreate()) {
			return dest.getMemory()
					.createInitializedBlock(entry.getBlockName(), entry.getDstMinAddress(),
						entry.getDstRange().getLength(), (byte) 0, monitor, entry.isOverlay());
		}
		MemoryBlock block = dest.getMemory().getBlock(entry.getDstMinAddress());
		if (plan.isRequiresInitializedMemory(source, dest) && !block.isInitialized()) {
			return dest.getMemory().convertToInitialized(block, (byte) 0);
		}
		return block;
	}

	protected void executeEntry(RangeEntry entry, Program dest, TraceRecorder recorder,
			TaskMonitor monitor) throws Exception {
		MemoryBlock block = executeEntryBlock(entry, dest, monitor);
		Address dstMin = entry.getDstRange().getMinAddress();
		if (block.isOverlay()) {
			dstMin = block.getStart().getAddressSpace().getAddress(dstMin.getOffset());
		}
		if (recorder != null) {
			executeCapture(entry.getSrcRange(), recorder, monitor);
		}
		plan.execute(source, entry.getSrcRange(), dest, dstMin, monitor);
	}

	protected TraceRecorder getRecorderIfEnabledAndReadsPresent() {
		if (!cbCapture.isSelected()) {
			return null;
		}
		return getRecorderIfReadsPresent();
	}

	protected void executeCapture(AddressRange range, TraceRecorder recorder, TaskMonitor monitor)
			throws Exception {
		synchronized (this) {
			monitor.checkCancelled();
			CompletableFuture<Void> recCapture =
				recorder.readMemoryBlocks(new AddressSet(range), monitor);
			this.captureTask = recCapture.thenCompose(__ -> {
				return recorder.getTarget().getModel().flushEvents();
			}).thenCompose(__ -> {
				return recorder.flushTransactions();
			});
		}
		try {
			captureTask.get(); // Not a fan, but whatever.
		}
		finally {
			captureTask = null;
		}
	}

	protected void executePlan(TaskMonitor monitor) throws Exception {
		Program dest = getDestination().getOrCreateProgram(source, this);
		boolean doRelease = !Arrays.asList(programManager.getAllOpenPrograms()).contains(dest);
		TraceRecorder recorder = getRecorderIfEnabledAndReadsPresent();
		try (Transaction tx = dest.openTransaction("Copy From Trace")) {
			monitor.initialize(tableModel.getRowCount());
			for (RangeEntry entry : tableModel.getModelData()) {
				monitor.setMessage("Copying into " + entry.getDstRange());
				executeEntry(entry, dest, recorder, monitor);
				monitor.incrementProgress(1);
			}
			programManager.openProgram(dest);
		}
		finally {
			if (doRelease) {
				dest.release(this);
			}
		}
		getDestination().saveIfApplicable(dest);
	}
}
