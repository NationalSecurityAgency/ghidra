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
package ghidra.app.plugin.core.debug.gui.console;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.TableModelEvent;
import javax.swing.table.*;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.LogEvent;

import docking.*;
import docking.action.*;
import docking.actions.PopupActionProvider;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.CustomToStringCellRenderer;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import generic.theme.GIcon;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.ClearAction;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.SelectNoneAction;
import ghidra.app.plugin.core.debug.utils.DebouncedRowWrappedEnumeratedColumnTableModel;
import ghidra.app.services.ProgressService;
import ghidra.debug.api.progress.MonitorReceiver;
import ghidra.debug.api.progress.ProgressListener;
import ghidra.framework.options.AutoOptions;
import ghidra.framework.options.annotation.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.annotation.AutoServiceConsumed;
import ghidra.util.*;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraTableFilterPanel;
import ghidra.util.table.column.GColumnRenderer;
import resources.Icons;

public class DebuggerConsoleProvider extends ComponentProviderAdapter
		implements PopupActionProvider {
	static final int ACTION_BUTTON_SIZE = 32;
	static final Dimension ACTION_BUTTON_DIM =
		new Dimension(ACTION_BUTTON_SIZE, ACTION_BUTTON_SIZE);
	static final int MIN_ROW_HEIGHT = 16;

	protected enum LogTableColumns implements EnumeratedTableColumn<LogTableColumns, LogRow<?>> {
		ICON("Icon", Icon.class, LogRow::getIcon, SortDirection.ASCENDING, false),
		MESSAGE("Message", Object.class, LogRow::getMessage, SortDirection.ASCENDING, false) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return HtmlOrProgressCellRenderer.INSTANCE;
			}
		},
		ACTIONS("Actions", ActionList.class, LogRow::getActions, SortDirection.DESCENDING, true) {
			private static final ConsoleActionsCellRenderer RENDERER =
				new ConsoleActionsCellRenderer();

			@Override
			public GColumnRenderer<?> getRenderer() {
				return RENDERER;
			}
		},
		TIME("Time", Date.class, LogRow::getDate, SortDirection.DESCENDING, false) {
			@Override
			public GColumnRenderer<?> getRenderer() {
				return CustomToStringCellRenderer.TIME_24HMSms;
			}
		};

		private final String header;
		private final Function<LogRow<?>, ?> getter;
		private final Class<?> cls;
		private final SortDirection defaultSortDirection;
		private final boolean editable;

		<T> LogTableColumns(String header, Class<T> cls, Function<LogRow<?>, T> getter,
				SortDirection defaultSortDirection, boolean editable) {
			this.header = header;
			this.cls = cls;
			this.getter = getter;
			this.defaultSortDirection = defaultSortDirection;
			this.editable = editable;
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
		public Object getValueOf(LogRow<?> row) {
			return getter.apply(row);
		}

		@Override
		public boolean isEditable(LogRow<?> row) {
			return editable;
		}

		@Override
		public void setValueOf(LogRow<?> row, Object value) {
		}

		@Override
		public SortDirection defaultSortDirection() {
			return defaultSortDirection;
		}
	}

	/**
	 * An action bound to a context
	 * 
	 * <p>
	 * This class is public for access by test cases only.
	 */
	public static class BoundAction {
		public final DockingActionIf action;
		public final ActionContext context;

		public BoundAction(DockingActionIf action, ActionContext context) {
			this.action = action;
			this.context = context;
		}

		@Override
		public String toString() {
			return getName();
		}

		public String getName() {
			return action.getName();
		}

		public Icon getIcon() {
			return action.getToolBarData().getIcon();
		}

		public boolean isEnabled() {
			return action.isEnabledForContext(context);
		}

		public String getTooltipText() {
			return action.getDescription();
		}

		public void perform() {
			action.actionPerformed(context);
		}
	}

	/**
	 * A list of bound actions
	 * 
	 * <p>
	 * This class is public for access by test cases only.
	 */
	public static class ActionList extends ArrayList<BoundAction> {
	}

	/**
	 * An entry in the console's log
	 * 
	 * <p>
	 * This class is public for access by test cases only.
	 */
	public interface LogRow<T> {
		Icon getIcon();

		T getMessage();

		ActionList getActions();

		Date getDate();

		ActionContext getActionContext();
	}

	static class MessageLogRow implements LogRow<String> {
		private final Icon icon;
		private final String message;
		private final Date date;
		private final ActionContext context;
		private final ActionList actions;

		public MessageLogRow(Icon icon, String message, Date date, ActionContext context,
				ActionList actions) {
			this.icon = icon;
			this.message = message;
			this.date = date;
			this.context = context;
			this.actions = Objects.requireNonNull(actions);
		}

		@Override
		public Icon getIcon() {
			return icon;
		}

		@Override
		public String getMessage() {
			return message;
		}

		@Override
		public Date getDate() {
			return date;
		}

		@Override
		public ActionContext getActionContext() {
			return context;
		}

		@Override
		public ActionList getActions() {
			return actions;
		}
	}

	static class MonitorLogRow implements LogRow<MonitorReceiver> {
		static final GIcon ICON = new GIcon("icon.pending");

		private final MonitorReceiver monitor;
		private final Date date;
		private final ActionContext context;
		private final ActionList actions;

		public MonitorLogRow(MonitorReceiver monitor, Date date, ActionContext context,
				ActionList actions) {
			this.monitor = monitor;
			this.date = date;
			this.context = context;
			this.actions = Objects.requireNonNull(actions);
		}

		@Override
		public Icon getIcon() {
			return ICON;
		}

		@Override
		public MonitorReceiver getMessage() {
			return monitor;
		}

		@Override
		public ActionList getActions() {
			return actions;
		}

		@Override
		public Date getDate() {
			return date;
		}

		@Override
		public ActionContext getActionContext() {
			return context;
		}
	}

	private class ListenerForProgress implements ProgressListener {
		final Map<MonitorReceiver, MonitorRowConsoleActionContext> contexts = new HashMap<>();
		CancelAction cancelAction = new CancelAction(plugin);

		ActionContext contextFor(MonitorReceiver monitor) {
			return contexts.computeIfAbsent(monitor, MonitorRowConsoleActionContext::new);
		}

		ActionList bindActions(ActionContext context) {
			ActionList actions = new ActionList();
			actions.add(new BoundAction(cancelAction, context));
			return actions;
		}

		@Override
		public void monitorCreated(MonitorReceiver monitor) {
			ActionContext context = contextFor(monitor);
			logRow(new MonitorLogRow(monitor, new Date(), context, bindActions(context)));
		}

		@Override
		public void monitorDisposed(MonitorReceiver monitor, Disposal disposal) {
			ActionContext context = contexts.remove(monitor);
			if (context == null) {
				context = new MonitorRowConsoleActionContext(monitor);
			}
			removeFromLog(context);
		}

		@Override
		public void messageUpdated(MonitorReceiver monitor, String message) {
			LogRow<?> logRow = logTableModel.getMap().get(contextFor(monitor));
			logTableModel.updateItem(logRow);
		}

		@Override
		public void progressUpdated(MonitorReceiver monitor, long progress) {
			LogRow<?> logRow = logTableModel.getMap().get(contextFor(monitor));
			logTableModel.updateItem(logRow);
		}

		@Override
		public void attributeUpdated(MonitorReceiver monitor) {
			LogRow<?> logRow = logTableModel.getMap().get(contextFor(monitor));
			logTableModel.updateItem(logRow);
		}
	}

	static class CancelAction extends DockingAction {
		static final Icon ICON = Icons.STOP_ICON;
		static final String HELP_ANCHOR = "cancel";

		public CancelAction(Plugin owner) {
			super("Cancel", owner.getName());
			setToolBarData(new ToolBarData(ICON));
			setHelpLocation(new HelpLocation(owner.getName(), HELP_ANCHOR));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			if (!(context instanceof MonitorRowConsoleActionContext ctx)) {
				return;
			}
			ctx.getMonitor().cancel();
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (!(context instanceof MonitorRowConsoleActionContext ctx)) {
				return false;
			}
			MonitorReceiver monitor = ctx.getMonitor();
			return monitor.isCancelEnabled() && !monitor.isCancelled();
		}
	}

	protected static class LogTableModel extends DebouncedRowWrappedEnumeratedColumnTableModel< //
			LogTableColumns, ActionContext, LogRow<?>, LogRow<?>> {

		public LogTableModel(PluginTool tool) {
			super(tool, "Log", LogTableColumns.class, r -> r == null ? null : r.getActionContext(),
				r -> r, r -> r);
		}

		@Override
		public List<LogTableColumns> defaultSortOrder() {
			return List.of(LogTableColumns.ACTIONS, LogTableColumns.TIME);
		}
	}

	protected static class LogTable extends GhidraTable {
		public LogTable(LogTableModel model) {
			super(model);
		}

		@Override
		public void tableChanged(TableModelEvent e) {
			super.tableChanged(e);
			Swing.runIfSwingOrRunLater(() -> updateRowHeights());
		}

		@Override
		public void columnMarginChanged(ChangeEvent e) {
			super.columnMarginChanged(e);
			// TODO: Debounce or otherwise delay this
			Swing.runIfSwingOrRunLater(() -> updateRowHeights());
		}

		protected void updateRowHeights() {
			// TODO: Be more selective in which rows
			//   Those changed
			//   Those visible?
			TableModel model = getModel();
			int rows = model.getRowCount();
			int cols = getColumnCount();
			for (int r = 0; r < rows; r++) {
				int height = MIN_ROW_HEIGHT;
				for (int c = 0; c < cols; c++) {
					height = Math.max(height, computePreferredHeight(r, c));
				}
				setRowHeight(r, height);
			}
		}

		protected int computePreferredHeight(int r, int c) {
			TableCellRenderer renderer = getCellRenderer(r, c);
			if (renderer instanceof ConsoleActionsCellRenderer) {
				ActionList actions =
					(ActionList) getModel().getValueAt(r, convertColumnIndexToModel(c));
				if (actions != null && !actions.isEmpty()) {
					return ACTION_BUTTON_SIZE + 2;
				}
				return 0;
			}
			if (renderer instanceof HtmlOrProgressCellRenderer custom) {
				int colWidth = getColumnModel().getColumn(c).getWidth();
				prepareRenderer(renderer, r, c);
				return custom.getRowHeight(colWidth);
			}
			return 0;
		}
	}

	private final DebuggerConsolePlugin plugin;

	// @AutoServiceConsumed via method
	private ProgressService progressService;
	@SuppressWarnings("unused")
	private final AutoService.Wiring autoServiceWiring;

	@AutoOptionDefined(
		name = DebuggerResources.OPTION_NAME_LOG_BUFFER_LIMIT,
		description = "The maximum number of entries in the console log (0 or less for unlimited)",
		help = @HelpInfo(anchor = "buffer_limit"))
	private int logBufferLimit = DebuggerResources.DEFAULT_LOG_BUFFER_LIMIT;
	@SuppressWarnings("unused")
	private final AutoOptions.Wiring autoOptionsWiring;

	protected final Map<String, Map<String, DockingActionIf>> actionsByOwnerThenName =
		new LinkedHashMap<>();

	protected final LogTableModel logTableModel;
	protected GhidraTable logTable;
	private GhidraTableFilterPanel<LogRow<?>> logFilterPanel;

	private Deque<LogRow<?>> buffer = new ArrayDeque<>();

	private final JPanel mainPanel = new JPanel(new BorderLayout());

	private final ListenerForProgress progressListener;

	DockingAction actionClear;
	DockingAction actionSelectNone;

	public DebuggerConsoleProvider(DebuggerConsolePlugin plugin) {
		super(plugin.getTool(), DebuggerResources.TITLE_PROVIDER_CONSOLE, plugin.getName());
		this.plugin = plugin;
		this.progressListener = new ListenerForProgress();

		logTableModel = new LogTableModel(tool);

		tool.addPopupActionProvider(this);

		setIcon(DebuggerResources.ICON_PROVIDER_CONSOLE);
		setHelpLocation(DebuggerResources.HELP_PROVIDER_CONSOLE);
		setWindowMenuGroup(DebuggerPluginPackage.NAME);

		buildMainPanel();

		this.autoServiceWiring = AutoService.wireServicesConsumed(plugin, this);
		this.autoOptionsWiring = AutoOptions.wireOptions(plugin, this);

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);
		createActions();
	}

	protected void dispose() {
		tool.removePopupActionProvider(this);
	}

	protected void buildMainPanel() {
		logTable = new LogTable(logTableModel);
		logTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		mainPanel.add(new JScrollPane(logTable));
		logFilterPanel = new GhidraTableFilterPanel<>(logTable, logTableModel);
		mainPanel.add(logFilterPanel, BorderLayout.NORTH);

		logTable.setRowHeight(ACTION_BUTTON_SIZE + 2);
		TableColumnModel columnModel = logTable.getColumnModel();

		TableColumn iconCol = columnModel.getColumn(LogTableColumns.ICON.ordinal());
		iconCol.setMaxWidth(24);
		iconCol.setMinWidth(24);

		TableColumn msgCol = columnModel.getColumn(LogTableColumns.MESSAGE.ordinal());
		msgCol.setPreferredWidth(150);

		TableColumn actCol = columnModel.getColumn(LogTableColumns.ACTIONS.ordinal());
		actCol.setPreferredWidth(50);
		actCol.setCellEditor(new ConsoleActionsCellEditor());

		TableColumn timeCol = columnModel.getColumn(LogTableColumns.TIME.ordinal());
		timeCol.setPreferredWidth(15);
	}

	protected void createActions() {
		actionClear = ClearAction.builder(plugin)
				.onAction(this::activatedClear)
				.buildAndInstallLocal(this);
		actionSelectNone = SelectNoneAction.builder(plugin)
				.popupWhen(ctx -> ctx.getSourceComponent() == logTable)
				.onAction(this::activatedSelectNone)
				.buildAndInstallLocal(this);
	}

	private void activatedClear(ActionContext ctx) {
		synchronized (buffer) {
			logTableModel.deleteItemsWith(r -> !(r instanceof MonitorLogRow));
			buffer.removeIf(r -> !(r instanceof MonitorLogRow));
		}
	}

	private void activatedSelectNone(ActionContext ctx) {
		logTable.clearSelection();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (logTable.getSelectedRowCount() != 1) {
			return super.getActionContext(event);
		}
		LogRow<?> sel = logFilterPanel.getSelectedItem();
		if (sel == null) {
			// I guess this can happen because of timing?
			return super.getActionContext(event);
		}
		return sel.getActionContext();
	}

	@AutoOptionConsumed(name = DebuggerResources.OPTION_NAME_LOG_BUFFER_LIMIT)
	private void setLogBufferLimit(int logBufferLimit) {
		truncateLog();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	protected void truncateLog() {
		synchronized (buffer) {
			while (logBufferLimit > 0 && buffer.size() > logBufferLimit) {
				logTableModel.deleteItem(buffer.removeFirst());
			}
		}
	}

	protected void log(Icon icon, String message) {
		log(icon, message, new LogRowConsoleActionContext());
	}

	protected void log(Icon icon, String message, ActionContext context) {
		logRow(
			new MessageLogRow(icon, message, new Date(), context, computeToolbarActions(context)));
	}

	protected void logRow(LogRow<?> row) {
		synchronized (buffer) {
			LogRow<?> old = logTableModel.deleteKey(row.getActionContext());
			if (old != null) {
				buffer.remove(old);
			}
			logTableModel.addItem(row);
			buffer.addLast(row);
			truncateLog();
		}
		//logTable.scrollRectToVisible(new Rectangle(0, Integer.MAX_VALUE - 1, 1, 1));
	}

	protected Icon iconForLevel(Level level) {
		if (level == Level.FATAL) {
			return DebuggerResources.ICON_LOG_FATAL;
		}
		else if (level == Level.ERROR) {
			return DebuggerResources.ICON_LOG_ERROR;
		}
		else if (level == Level.WARN) {
			return DebuggerResources.ICON_LOG_WARN;
		}
		return null;
	}

	protected void logEvent(LogEvent event) {
		ActionContext context = new LogRowConsoleActionContext();
		logRow(new MessageLogRow(iconForLevel(event.getLevel()),
			"<html>" + HTMLUtilities.escapeHTML(event.getMessage().getFormattedMessage()),
			new Date(event.getTimeMillis()), context, computeToolbarActions(context)));
	}

	protected void removeFromLog(ActionContext context) {
		synchronized (buffer) {
			LogRow<?> r = logTableModel.deleteKey(context);
			buffer.remove(r);
		}
	}

	protected boolean logContains(ActionContext context) {
		synchronized (buffer) {
			return logTableModel.getMap().containsKey(context);
		}
	}

	protected List<ActionContext> getActionContexts() {
		synchronized (buffer) {
			return List.copyOf(logTableModel.getMap().keySet());
		}
	}

	protected void addResolutionAction(DockingActionIf action) {
		DockingActionIf replaced =
			actionsByOwnerThenName.computeIfAbsent(action.getOwner(), o -> new LinkedHashMap<>())
					.put(action.getName(), action);
		if (replaced != null) {
			Msg.warn(this, "Duplicate resolution action registered: " + action.getFullName());
		}
	}

	protected void removeResolutionAction(DockingActionIf action) {
		Map<String, DockingActionIf> byName = actionsByOwnerThenName.get(action.getOwner());
		if (byName == null) {
			Msg.warn(this, "Action to remove was never added: " + action.getFullName());
			return;
		}
		DockingActionIf removed = byName.get(action.getName());
		if (removed != action) {
			if (removed != null) {
				Msg.warn(this,
					"Action to remove did not match that added: " + action.getFullName());
			}
			else {
				Msg.warn(this, "Action to removed was never added: " + action.getFullName());
			}
			return;
		}
		if (byName.isEmpty()) {
			actionsByOwnerThenName.remove(action.getOwner());
		}
	}

	protected Stream<DockingActionIf> streamActions(ActionContext context) {
		return actionsByOwnerThenName.values()
				.stream()
				.flatMap(m -> m.values().stream())
				.filter(a -> a.isValidContext(context));
	}

	protected ActionList computeToolbarActions(ActionContext context) {
		return streamActions(context)
				.filter(a -> a.getToolBarData() != null)
				.map(a -> new BoundAction(a, context))
				.collect(Collectors.toCollection(ActionList::new));
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context) {
		return streamActions(context)
				.filter(a -> a.isAddToPopup(context))
				.collect(Collectors.toList());
	}

	protected long getRowCount(Class<? extends ActionContext> ctxCls) {
		synchronized (buffer) {
			return logTableModel.getModelData()
					.stream()
					.filter(r -> ctxCls.isInstance(r.getActionContext()))
					.count();
		}
	}

	public LogRow<?> getLogRow(ActionContext ctx) {
		synchronized (buffer) {
			return logTableModel.getMap().get(ctx);
		}
	}

	@AutoServiceConsumed
	private void setProgressService(ProgressService progressService) {
		if (this.progressService != null) {
			this.progressService.removeProgressListener(progressListener);
		}
		this.progressService = progressService;
		if (this.progressService != null) {
			this.progressService.addProgressListener(progressListener);
		}
		resyncProgressRows();
	}

	private void resyncProgressRows() {
		synchronized (buffer) {
			logTableModel.deleteItemsWith(r -> r instanceof MonitorLogRow);
			if (progressService == null) {
				return;
			}
			for (MonitorReceiver monitor : progressService.getAllMonitors()) {
				if (!monitor.isValid()) {
					continue;
				}
				progressListener.monitorCreated(monitor);
			}
		}
	}
}
