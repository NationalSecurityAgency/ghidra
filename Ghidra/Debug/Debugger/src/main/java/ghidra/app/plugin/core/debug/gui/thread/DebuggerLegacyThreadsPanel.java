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
package ghidra.app.plugin.core.debug.gui.thread;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.event.*;
import java.util.function.BiConsumer;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.*;

import docking.ActionContext;
import docking.widgets.table.*;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import docking.widgets.table.RangeCursorTableHeaderRenderer.SeekListener;
import ghidra.app.plugin.core.debug.gui.DebuggerSnapActionContext;
import ghidra.app.services.DebuggerTraceManagerService;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.docking.settings.Settings;
import ghidra.framework.model.DomainObjectChangeRecord;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.plugintool.AutoService;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.program.model.address.Address;
import ghidra.trace.model.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.thread.TraceThreadManager;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.util.TraceEvents;
import ghidra.util.database.ObjectKey;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.AbstractGColumnRenderer;

public class DebuggerLegacyThreadsPanel extends JPanel {

	protected static long orZero(Long l) {
		return l == null ? 0 : l;
	}

	protected enum ThreadTableColumns
		implements EnumeratedTableColumn<ThreadTableColumns, ThreadRow> {
		NAME("Name", String.class, ThreadRow::getName, ThreadRow::setName, true, true),
		PC("PC", Address.class, ThreadRow::getProgramCounter, true, true),
		FUNCTION("Function", ghidra.program.model.listing.Function.class, ThreadRow::getFunction, //
				true, true),
		MODULE("Module", String.class, ThreadRow::getModule, true, false),
		SP("SP", Address.class, ThreadRow::getStackPointer, true, false),
		CREATED("Created", Long.class, ThreadRow::getCreationSnap, true, false),
		DESTROYED("Destroyed", String.class, ThreadRow::getDestructionSnap, true, false),

		STATE("State", ThreadState.class, ThreadRow::getState, true, true),
		COMMENT("Comment", String.class, ThreadRow::getComment, ThreadRow::setComment, true, false),
		PLOT("Plot", Lifespan.class, ThreadRow::getLifespan, false, true);

		private final String header;
		private final Function<ThreadRow, ?> getter;
		private final BiConsumer<ThreadRow, Object> setter;
		private final boolean sortable;
		private final boolean visible;
		private final Class<?> cls;

		<T> ThreadTableColumns(String header, Class<T> cls, Function<ThreadRow, T> getter,
				boolean sortable, boolean visible) {
			this(header, cls, getter, null, sortable, visible);
		}

		@SuppressWarnings("unchecked")
		<T> ThreadTableColumns(String header, Class<T> cls, Function<ThreadRow, T> getter,
				BiConsumer<ThreadRow, T> setter, boolean sortable, boolean visible) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.setter = (BiConsumer<ThreadRow, Object>) setter;
			this.sortable = sortable;
			this.visible = visible;
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
		public Object getValueOf(ThreadRow row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(ThreadRow row) {
			return setter != null;
		}

		@Override
		public boolean isSortable() {
			return sortable;
		}

		@Override
		public boolean isVisible() {
			return visible;
		}

		@Override
		public void setValueOf(ThreadRow row, Object value) {
			setter.accept(row, value);
		}
	}

	protected static class ThreadTableModel extends RowWrappedEnumeratedColumnTableModel< //
			ThreadTableColumns, ObjectKey, ThreadRow, TraceThread> {

		public ThreadTableModel(DebuggerThreadsProvider provider) {
			super(provider.getTool(), "Threads", ThreadTableColumns.class,
				TraceThread::getObjectKey, t -> new ThreadRow(provider, t), ThreadRow::getThread);
		}
	}

	private class ForThreadsListener extends TraceDomainObjectListener {
		public ForThreadsListener() {
			listenForUntyped(DomainObjectEvent.RESTORED, this::objectRestored);

			listenFor(TraceEvents.THREAD_ADDED, this::threadAdded);
			listenFor(TraceEvents.THREAD_CHANGED, this::threadChanged);
			listenFor(TraceEvents.THREAD_LIFESPAN_CHANGED, this::threadChanged);
			listenFor(TraceEvents.THREAD_DELETED, this::threadDeleted);

			listenFor(TraceEvents.SNAPSHOT_ADDED, this::snapAdded);
			listenFor(TraceEvents.SNAPSHOT_DELETED, this::snapDeleted);
		}

		private void objectRestored(DomainObjectChangeRecord rec) {
			loadThreads();
		}

		private void threadAdded(TraceThread thread) {
			threadTableModel.addItem(thread);
		}

		private void threadChanged(TraceThread thread) {
			threadTableModel.updateItem(thread);
		}

		private void threadDeleted(TraceThread thread) {
			threadTableModel.deleteItem(thread);
		}

		private void snapAdded(TraceSnapshot snapshot) {
			updateTimelineMax();
		}

		private void snapDeleted() {
			updateTimelineMax();
		}
	}

	private final DebuggerThreadsProvider provider;

	DebuggerCoordinates current = DebuggerCoordinates.NOWHERE;
	private Trace currentTrace; // Copy for transition

	@AutoServiceConsumed
	private DebuggerTraceManagerService traceManager;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	private final ForThreadsListener forThreadsListener = new ForThreadsListener();

	/* package access for testing */
	final SpanTableCellRenderer<Long> spanRenderer = new SpanTableCellRenderer<>();
	final RangeCursorTableHeaderRenderer<Long> headerRenderer;

	final TableCellRenderer boldCurrentRenderer = new AbstractGColumnRenderer<Object>() {
		@Override
		public String getFilterString(Object t, Settings settings) {
			return t == null ? "<null>" : t.toString();
		}

		@Override
		public Component getTableCellRendererComponent(GTableCellRenderingData data) {
			super.getTableCellRendererComponent(data);
			ThreadRow row = (ThreadRow) data.getRowObject();
			if (row != null && row.getThread() == current.getThread()) {
				setBold();
			}
			return this;
		}
	};

	final ThreadTableModel threadTableModel;
	final GTable threadTable;
	final GhidraTableFilterPanel<ThreadRow> threadFilterPanel;

	private ActionContext myActionContext;

	// strong ref
	SeekListener seekListener;

	public DebuggerLegacyThreadsPanel(DebuggerThreadsPlugin plugin,
			DebuggerThreadsProvider provider) {
		super(new BorderLayout());
		this.provider = provider;

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);

		threadTableModel = new ThreadTableModel(provider);
		headerRenderer = new RangeCursorTableHeaderRenderer<>(0L,
			threadTableModel.getColumn(ThreadTableColumns.PLOT.ordinal()));
		threadTable = new GhidraTable(threadTableModel);
		threadTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		add(new JScrollPane(threadTable));
		threadFilterPanel = new GhidraTableFilterPanel<>(threadTable, threadTableModel);
		add(threadFilterPanel, BorderLayout.SOUTH);

		myActionContext = new DebuggerSnapActionContext(current.getTrace(), current.getViewSnap());

		threadTable.getSelectionModel().addListSelectionListener(this::threadRowSelected);
		threadTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2 && e.getButton() == MouseEvent.BUTTON1) {
					activateSelectedThread();
				}
			}
		});
		threadTable.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER) {
					activateSelectedThread();
					e.consume(); // lest it select the next row down
				}
			}
		});
		threadTable.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				setThreadRowActionContext();
			}
		});
		threadTable.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				setThreadRowActionContext();
			}
		});

		TableColumnModel columnModel = threadTable.getColumnModel();
		TableColumn colName = columnModel.getColumn(ThreadTableColumns.NAME.ordinal());
		colName.setCellRenderer(boldCurrentRenderer);
		TableColumn colCreated = columnModel.getColumn(ThreadTableColumns.CREATED.ordinal());
		colCreated.setCellRenderer(boldCurrentRenderer);
		TableColumn colDestroyed = columnModel.getColumn(ThreadTableColumns.DESTROYED.ordinal());
		colDestroyed.setCellRenderer(boldCurrentRenderer);
		TableColumn colState = columnModel.getColumn(ThreadTableColumns.STATE.ordinal());
		colState.setCellRenderer(boldCurrentRenderer);
		TableColumn colComment = columnModel.getColumn(ThreadTableColumns.COMMENT.ordinal());
		colComment.setCellRenderer(boldCurrentRenderer);
		TableColumn colPlot = columnModel.getColumn(ThreadTableColumns.PLOT.ordinal());
		colPlot.setCellRenderer(spanRenderer);
		colPlot.setHeaderRenderer(headerRenderer);

		headerRenderer.addSeekListener(seekListener = pos -> {
			long snap = Math.round(pos);
			if (snap < 0) {
				snap = 0;
			}
			long max =
				current.getTrace() == null ? 0 : current.getTrace().getTimeManager().getMaxSnap();
			if (snap > max) {
				snap = max;
			}
			traceManager.activateSnap(snap);
			myActionContext = new DebuggerSnapActionContext(current.getTrace(), snap);
			provider.legacyThreadsPanelContextChanged();
		});
	}

	private void removeOldListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.removeListener(forThreadsListener);
	}

	private void addNewListeners() {
		if (currentTrace == null) {
			return;
		}
		currentTrace.addListener(forThreadsListener);
	}

	private void doSetTrace(Trace trace) {
		if (currentTrace == trace) {
			return;
		}
		removeOldListeners();
		currentTrace = trace;
		addNewListeners();

		loadThreads();
	}

	protected void coordinatesActivated(DebuggerCoordinates coordinates) {
		current = coordinates;
		doSetTrace(coordinates.getTrace());
		doSetThread(coordinates.getThread());
		doSetSnap(coordinates.getSnap());
	}

	private void doSetThread(TraceThread thread) {
		if (thread != null) {
			threadFilterPanel.setSelectedItem(threadTableModel.getRow(thread));
		}
		else {
			threadTable.clearSelection();
		}
		threadTableModel.fireTableDataChanged();
	}

	private void doSetSnap(long snap) {
		headerRenderer.setCursorPosition(snap);
		threadTable.getTableHeader().repaint();
	}

	protected void loadThreads() {
		threadTableModel.clear();
		Trace curTrace = current.getTrace();
		if (curTrace == null) {
			return;
		}
		TraceThreadManager manager = curTrace.getThreadManager();
		threadTableModel.addAllItems(manager.getAllThreads());
		updateTimelineMax();
	}

	protected void updateTimelineMax() {
		Trace trace = current.getTrace();
		long max = orZero(trace == null ? null : trace.getTimeManager().getMaxSnap());
		Lifespan fullRange = Lifespan.span(0, max + 1);
		spanRenderer.setFullRange(fullRange);
		headerRenderer.setFullRange(fullRange);
		threadTable.getTableHeader().repaint();
	}

	private void threadRowSelected(ListSelectionEvent e) {
		if (e.getValueIsAdjusting()) {
			return;
		}
		setThreadRowActionContext();
	}

	private void activateSelectedThread() {
		ThreadRow row = setThreadRowActionContext();
		if (row != null && traceManager != null) {
			traceManager.activateThread(row.getThread());
		}
	}

	public ActionContext getActionContext() {
		return myActionContext;
	}

	private ThreadRow setThreadRowActionContext() {
		ThreadRow row = threadFilterPanel.getSelectedItem();
		myActionContext = new DebuggerThreadActionContext(current.getTrace(),
			row == null ? null : row.getThread());
		provider.legacyThreadsPanelContextChanged();
		return row;
	}
}
