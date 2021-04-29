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
package ghidra.app.plugin.core.bookmark;

import java.awt.event.KeyEvent;
import java.util.*;

import javax.swing.Icon;
import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.*;
import docking.actions.PopupActionProvider;
import docking.widgets.table.GTable;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.*;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.Msg;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.task.SwingUpdateManager;
import resources.*;

/**
 * Plugin to for adding/deleting/editing bookmarks.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.CODE_VIEWER,
	shortDescription = "Manage Bookmarks",
	description = "This plugin allows the user to add, edit, " +
			"delete, and show bookmarks. It adds navigation markers at " +
			"addresses where bookmarks reside.",
	servicesRequired = { GoToService.class, MarkerService.class },
	servicesProvided = { BookmarkService.class },
	eventsProduced = { ProgramSelectionPluginEvent.class }
)
//@formatter:on
public class BookmarkPlugin extends ProgramPlugin
		implements DomainObjectListener, PopupActionProvider, BookmarkService {

	private final static int MAX_DELETE_ACTIONS = 10;

	final static int TIMER_DELAY = 500;

	public static final int MIN_TIMEOUT = 1000;
	public static final int MAX_TIMEOUT = 1000 * 60 * 20;

	private BookmarkProvider provider;
	private DockingAction addAction;
	private DockingAction deleteAction;
	private CreateBookmarkDialog createDialog;
	private GoToService goToService;
	private MarkerService markerService;
	private BookmarkManager bookmarkMgr;
	private SwingUpdateManager repaintMgr;

	private Map<String, BookmarkNavigator> bookmarkNavigators = new HashMap<>(); // maps type names to BookmarkNavigators
	private NavUpdater navUpdater;

	public BookmarkPlugin(PluginTool tool) {
		super(tool, true, true);

		provider = new BookmarkProvider(tool, this);
		provider.addToTool();

		createActions();
	}

	@Override
	public void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);
		provider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		if (provider != null) {
			provider.writeConfigState(saveState);
		}
	}

	/**
	 * Create actions for this plugin.
	 */
	private void createActions() {
		addAction = new AddBookmarkAction(this);
		addAction.setEnabled(true);
		tool.addAction(addAction);

		MultiIconBuilder builder = new MultiIconBuilder(Icons.CONFIGURE_FILTER_ICON);
		builder.addLowerRightIcon(ResourceManager.loadImage("images/check.png"));
		Icon filterTypesChanged = builder.build();
		Icon filterTypesUnchanged = Icons.CONFIGURE_FILTER_ICON;
		DockingAction filterAction = new DockingAction("Filter Bookmarks", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				filterBookmarks();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {

				if (currentProgram == null) {
					setToolBarData(new ToolBarData(filterTypesUnchanged));
					return false;
				}

				// the FilterDialog uses a program to determine what filter types are available
				boolean hasTypeFilter = provider.hasTypeFilterApplied();
				Icon icon = hasTypeFilter ? filterTypesChanged : filterTypesUnchanged;
				setToolBarData(new ToolBarData(icon));
				return true;
			}
		};

		filterAction.setToolBarData(new ToolBarData(filterTypesUnchanged));
		filterAction.setDescription("Adjust Filters");
		tool.addLocalAction(provider, filterAction);

		deleteAction = new DockingAction("Delete Bookmarks", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				provider.delete();
			}
		};
		Icon icon = ResourceManager.loadImage("images/edit-delete.png");
		deleteAction.setKeyBindingData(new KeyBindingData(KeyEvent.VK_DELETE, 0));
		deleteAction.setPopupMenuData(new MenuData(new String[] { "Delete" }, icon));
		deleteAction.setDescription("Delete Selected Bookmarks");
		deleteAction.setEnabled(true);
		deleteAction.setToolBarData(new ToolBarData(icon));
		tool.addLocalAction(provider, deleteAction);

		DockingAction selectionAction = new DockingAction("Select Bookmark Locations", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				select(provider.getBookmarkLocations());
			}
		};
		icon = ResourceManager.loadImage("images/text_align_justify.png");
		selectionAction.setPopupMenuData(
			new MenuData(new String[] { "Select Bookmark Locations" }, icon));
		selectionAction.setToolBarData(new ToolBarData(icon));
		selectionAction.setEnabled(true);
		tool.addLocalAction(provider, selectionAction);

		DockingAction selectionNavigationAction =
			new SelectionNavigationAction(this, provider.getTable());
		tool.addLocalAction(provider, selectionNavigationAction);
	}

	/**
	 * Display a dialog to set up a filter on the displayed bookmarks.
	 */
	public void filterBookmarks() {
		FilterDialog d = new FilterDialog(provider, currentProgram);
		tool.showDialog(d, provider);
		provider.contextChanged();
	}

	/**
	 * Get rid of any resources this plugin is using
	 * before the plugin is destroyed.
	 */
	@Override
	public synchronized void dispose() {
		navUpdater.dispose();

		tool.removePopupActionProvider(this);
		if (repaintMgr != null) {
			repaintMgr.dispose();
		}
		if (addAction != null) {
			addAction.dispose();
			addAction = null;
		}
		if (provider != null) {
			provider.dispose();
			provider = null;
		}
		if (createDialog != null) {
			createDialog.dispose();
			createDialog = null;
		}
		goToService = null;

		disposeAllBookmarkers();
		markerService = null;

		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		currentProgram = null;
		super.dispose();
	}

	/**
	 * Acquires <code>GoToService</code> if available.
	 */
	@Override
	protected void init() {
		goToService = tool.getService(GoToService.class);
		provider.setGoToService(goToService);
		markerService = tool.getService(MarkerService.class);

		tool.addPopupActionProvider(this);

		navUpdater = new NavUpdater();
		repaintMgr = new SwingUpdateManager(500, () -> provider.repaint());

	}

	MarkerService getMarkerService() {
		return markerService;
	}

	private void initializeBookmarkers() {
		if (currentProgram == null) {
			return;
		}

		final BookmarkManager mgr = currentProgram.getBookmarkManager();
		BookmarkNavigator.defineBookmarkTypes(currentProgram);

		Runnable r = () -> {
			if (currentProgram == null) {
				return;
			}
			synchronized (BookmarkPlugin.this) {
				// Initialize markers after all plugins have defined the various bookmark types
				BookmarkType[] types = mgr.getBookmarkTypes();
				for (BookmarkType element : types) {
					getBookmarkNavigator(element);
					scheduleUpdate(element.getTypeString());
				}
			}
		};
		SwingUtilities.invokeLater(r);
	}

	private void disposeAllBookmarkers() {
		Iterator<BookmarkNavigator> it = bookmarkNavigators.values().iterator();
		while (it.hasNext()) {
			BookmarkNavigator nav = it.next();
			nav.dispose();
		}
		bookmarkNavigators.clear();
	}

	/**
	 * Get or create a bookmark navigator for the specified bookmark type
	 * @param type the bookmark type
	 * @return bookmark navigator
	 */
	private BookmarkNavigator getBookmarkNavigator(BookmarkType type) {
		if (type == null) {
			return null;
		}
		String typeString = type.getTypeString();
		BookmarkNavigator nav = bookmarkNavigators.get(typeString);
		if (nav == null) {
			nav = new BookmarkNavigator(markerService, currentProgram.getBookmarkManager(), type);
			bookmarkNavigators.put(typeString, nav);
		}
		return nav;
	}

	private synchronized void scheduleUpdate(String type) {
		navUpdater.addType(type);
	}

	@Override
	public synchronized void domainObjectChanged(DomainObjectChangedEvent ev) {

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_MOVED) ||
			ev.containsEvent(ChangeManager.DOCR_MEMORY_BLOCK_REMOVED)) {
			scheduleUpdate(null);
			provider.reload();
			return;
		}

		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord record = ev.getChangeRecord(i);

			int eventType = record.getEventType();
			if (!(record instanceof ProgramChangeRecord)) {
				continue;
			}
			switch (eventType) {

				case ChangeManager.DOCR_BOOKMARK_REMOVED: {
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Bookmark bookmark = (Bookmark) rec.getObject();
					bookmarkRemoved(bookmark);
					break;
				}

				case ChangeManager.DOCR_BOOKMARK_ADDED: {
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Bookmark bookmark = (Bookmark) rec.getObject();
					bookmarkAdded(bookmark);
					break;
				}

				case ChangeManager.DOCR_BOOKMARK_CHANGED: {
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					Bookmark bookmark = (Bookmark) rec.getObject();
					bookmarkChanged(bookmark);
					break;
				}

				case ChangeManager.DOCR_BOOKMARK_TYPE_ADDED: {
					ProgramChangeRecord rec = (ProgramChangeRecord) ev.getChangeRecord(i);
					BookmarkType bookmarkType = (BookmarkType) rec.getObject();
					if (bookmarkType != null) {
						typeAdded(bookmarkType.getTypeString());
					}
					break;
				}
				default:
					repaintMgr.update();

			}
		}
	}

	@Override
	public void setBookmarksVisible(boolean visible) {
		tool.showComponentProvider(provider, visible);
	}

	private void typeAdded(String type) {
		provider.typeAdded(type);
		getBookmarkNavigator(bookmarkMgr.getBookmarkType(type));
	}

	private void bookmarkChanged(Bookmark bookmark) {
		if (bookmark == null) {
			scheduleUpdate(null);
			provider.reload();
			return;
		}
		BookmarkNavigator nav = getBookmarkNavigator(bookmark.getType());
		nav.add(bookmark.getAddress());
		scheduleUpdate(bookmark.getType().getTypeString());
		provider.bookmarkChanged(bookmark);
	}

	private void bookmarkAdded(Bookmark bookmark) {
		if (bookmark == null) {
			scheduleUpdate(null);
			provider.reload();
			return;
		}
		BookmarkNavigator nav = getBookmarkNavigator(bookmark.getType());
		nav.add(bookmark.getAddress());
//		scheduleUpdate(bookmark.getType().getTypeString());
		provider.bookmarkAdded(bookmark);
	}

	private void bookmarkRemoved(Bookmark bookmark) {
		if (bookmark == null) {
			scheduleUpdate(null);
			provider.reload();
			return;
		}
		String type = bookmark.getTypeString();
		BookmarkNavigator nav = bookmarkNavigators.get(type);
		if (nav != null) {
			Address addr = bookmark.getAddress();
			Bookmark[] bookmarks = currentProgram.getBookmarkManager().getBookmarks(addr, type);
			if (bookmarks.length == 0) {
				nav.clear(addr);
			}
		}
		provider.bookmarkRemoved(bookmark);
	}

	@Override
	protected synchronized void programDeactivated(Program program) {
		provider.setProgram(null);
		navUpdater.setProgram(null);
		program.removeListener(this);
		disposeAllBookmarkers();
		bookmarkMgr = null;
	}

	@Override
	public Object getTransientState() {
		return provider.getFilterState();
	}

	@Override
	public void restoreTransientState(Object state) {
		provider.restoreFilterState((FilterState) state);
	}

	@Override
	protected synchronized void programActivated(Program program) {
		program.addListener(this);
		navUpdater.setProgram(program);
		initializeBookmarkers();
		provider.setProgram(program);
		bookmarkMgr = program.getBookmarkManager();
	}

	void showAddBookmarkDialog(Address location) {
		Listing listing = currentProgram.getListing();
		CodeUnit currCU = listing.getCodeUnitContaining(location);
		if (currCU == null) {
			return;
		}
		boolean hasSelection = currentSelection != null && !currentSelection.isEmpty();
		createDialog = new CreateBookmarkDialog(this, currCU, hasSelection);
		tool.showDialog(createDialog);
	}

	/**
	 * Called when a new bookmark is to be added; called from the add bookmark dialog
	 * 
	 * @param addr bookmark address.  If null a Note bookmark will set at the 
	 * 		  start address of each range in the current selection
	 * @param category bookmark category
	 * @param comment comment text
	 */
	public void setNote(Address addr, String category, String comment) {

		CompoundCmd cmd = new CompoundCmd("Set Note Bookmark");

		if (addr != null) {
			// Add address specified within bookmark
			cmd.add(new BookmarkDeleteCmd(addr, BookmarkType.NOTE));
			cmd.add(new BookmarkEditCmd(addr, BookmarkType.NOTE, category, comment));
		}
		else {

			// Create address set with first address only
			AddressSet set = new AddressSet();
			AddressRangeIterator iter = currentSelection.getAddressRanges();
			while (iter.hasNext()) {
				Address minAddr = iter.next().getMinAddress();
				set.addRange(minAddr, minAddr);
			}

			// Add a bookmark at the first address of each address range in
			//   the current selection
			cmd.add(new BookmarkDeleteCmd(set, BookmarkType.NOTE));
			cmd.add(new BookmarkEditCmd(set, BookmarkType.NOTE, category, comment));
		}
		tool.execute(cmd, currentProgram);
	}

	void deleteBookmark(Bookmark bookmark) {
		BookmarkDeleteCmd cmd = new BookmarkDeleteCmd(bookmark);
		tool.execute(cmd, currentProgram);
	}

	private void select(ProgramSelection selection) {
		firePluginEvent(new ProgramSelectionPluginEvent(getName(), selection, currentProgram));
	}

	@Override
	public List<DockingActionIf> getPopupActions(Tool activeTool, ActionContext context) {
		Object contextObject = context.getContextObject();
		if (!(contextObject instanceof MarkerLocation)) {
			return null;
		}
		MarkerLocation loc = (MarkerLocation) contextObject;
		BookmarkManager mgr = currentProgram.getBookmarkManager();
		Address address = loc.getAddr();
		Bookmark[] bookmarks = mgr.getBookmarks(address);

		List<DockingActionIf> defaultBookmarkList = new ArrayList<>();
		for (Bookmark element : bookmarks) {
			DockingAction action = new DeleteBookmarkAction(this, element, false);
			action.setEnabled(true);
			defaultBookmarkList.add(action);
		}

		// add the delete actions at the current address
		List<DockingActionIf> popupActionList = new ArrayList<>();
		addActionsToList(popupActionList, defaultBookmarkList, MAX_DELETE_ACTIONS);

		// add the delete actions for the surrounding code unit
		List<DockingActionIf> actionsForCodeUnitList =
			getActionsForCodeUnit(address, MAX_DELETE_ACTIONS - popupActionList.size());
		addActionsToList(popupActionList, actionsForCodeUnitList, MAX_DELETE_ACTIONS);

		return popupActionList;
	}

	/**
	 * Returns a list of actions to delete bookmarks that are in the code unit surrounding the 
	 * given address.  The list of actions will not exceed <tt>maxActionsCount</tt>
	 * @param  primaryAddress The address required to find the containing code unit.
	 * @param  maxActionsCount The maximum number of actions to include in the returned list.
	 * @return a list of actions to delete bookmarks that are in the code unit surrounding the 
	 *         given address.
	 */
	private List<DockingActionIf> getActionsForCodeUnit(Address primaryAddress,
			int maxActionsCount) {
		List<DockingActionIf> actionList = new ArrayList<>();

		Iterator<String> iter = bookmarkNavigators.keySet().iterator();
		while (iter.hasNext() && actionList.size() < maxActionsCount) {
			String bookmarkType = iter.next();
			BookmarkNavigator navigator = bookmarkNavigators.get(bookmarkType);

			List<DockingActionIf> typeDeleteActionList =
				getActionsForCodeUnitAndType(primaryAddress, bookmarkType, navigator);
			addActionsToList(actionList, typeDeleteActionList, maxActionsCount);
		}

		return actionList;
	}

	/**
	 * Returns a list of actions to delete bookmarks that are in the code unit surrounding the 
	 * given address <b>for the given <i>type</i> of bookmark</b>.
	 * @param primaryAddress The address required to find the containing code unit.
	 * @param type The bookmark type to retrieve.
	 * @param navigator The BookmarkNavigator used to determine whether there are bookmarks 
	 *        inside the code unit containing the given <tt>primaryAddress</tt>.
	 * @return a list of actions to delete bookmarks that are in the code unit surrounding the 
	 *         given address <b>for the given <i>type</i> of bookmark</b>.
	 */
	private List<DockingActionIf> getActionsForCodeUnitAndType(Address primaryAddress, String type,
			BookmarkNavigator navigator) {

		// find all bookmarks that may be within the code unit at address
		List<DockingActionIf> actionList = new ArrayList<>();
		CodeUnit cu = currentProgram.getListing().getCodeUnitContaining(primaryAddress);
		if (cu == null) {
			return actionList;
		}
		Address start = cu.getMinAddress();
		Address end = cu.getMaxAddress();

		if (!navigator.intersects(start, end)) {
			return actionList;
		}

		for (int i = 1; i < cu.getLength(); i++) {
			Address nextCodeUnitAddress = start.add(i);
			if (!nextCodeUnitAddress.equals(primaryAddress)) { // skip the original location                    
				Bookmark[] otherBookmarks = bookmarkMgr.getBookmarks(nextCodeUnitAddress, type);
				if (otherBookmarks.length > 0) {
					DockingAction action = new DeleteBookmarkAction(this, otherBookmarks[0], true);
					action.setEnabled(true);
					actionList.add(action);
				}
			}
		}
		return actionList;
	}

	/**
	 * Adds the actions in <tt>newActionList</tt> to <tt>actionList</tt> while the size of
	 * <tt>actionList</tt> is less than the given {@link #MAX_DELETE_ACTIONS}.
	 * @param actionList The list to add to
	 * @param newActionList The list containing items to add
	 * @param maxActionCount the maximum number of items that the actionList can contain 
	 */
	private void addActionsToList(List<DockingActionIf> actionList,
			List<DockingActionIf> newActionList, int maxActionCount) {
		for (int i = 0; i < newActionList.size() && actionList.size() < maxActionCount; i++) {
			actionList.add(newActionList.get(i));
		}
	}

	/**
	 * Runner used in thread to update bookmark display in the marker margins.
	 */
	private class NavUpdater implements Runnable {
		private Set<String> types = new HashSet<>();
		private SwingUpdateManager updateMgr;
		private boolean running;
		private volatile Program program;

		NavUpdater() {
			updateMgr = new SwingUpdateManager(MIN_TIMEOUT, MAX_TIMEOUT, () -> timerExpired());
		}

		private synchronized void timerExpired() {
			if (running) {
				updateMgr.updateLater();
			}
			else {
				Thread t = new Thread(this, "Bookmark Plugin Nav Updater");
				t.setDaemon(true);
				t.setPriority(Thread.MIN_PRIORITY + 1);
				t.setName("Bookmark Navigation Update");
				t.start();
			}
		}

		public synchronized void addType(String type) {
			if (type != null) {
				types.add(type);
			}
			else {
				Iterator<String> it = bookmarkNavigators.keySet().iterator();
				while (it.hasNext()) {
					types.add(it.next());
				}
			}
			updateMgr.update();
		}

		void dispose() {
			updateMgr.dispose();
		}

		synchronized void setProgram(Program program) {
			this.program = program;
			types.clear();
		}

		@Override
		public void run() {
			Program myProgram = program;
			Set<String> myTypes = null;
			synchronized (this) {
				if (types.isEmpty()) {
					// the program has been changed or closed
					return;
				}
				myTypes = types;
				types = new HashSet<>();
				running = true;
			}
			try {
				Iterator<String> it = myTypes.iterator();
				while (it.hasNext()) {
					String type = it.next();
					updateNav(type);
				}
			}
			catch (Throwable t) {
				// This is squashed due to the nature of this primitive thread.  This thread 
				// may still be running while the program it is working on is changed or 
				// closed.  Since this thread is transient and is just a helper thread to update
				// bookmarks, the decision was made to just squash generated exceptions. 

				// Try a bit to uncover real problems: a disposed updated manager or a different
				// program would signal that this thread has been obsoleted.
				if (!updateMgr.isDisposed() && program == myProgram) {
					Msg.showError(BookmarkPlugin.this, null, "Unexpected Error",
						"Unexpected exception update bookmark markers", t);
				}
			}
			synchronized (this) {
				running = false;
			}
		}

		private void updateNav(String type) {
			BookmarkNavigator nav = bookmarkNavigators.get(type);
			if (nav != null) {
				nav.updateBookmarkers(getAddresses(type));
			}
		}

		private AddressSet getAddresses(String type) {

			AddressSet set = new AddressSet();
			Iterator<Bookmark> it = bookmarkMgr.getBookmarksIterator(type);
			while (it.hasNext()) {
				Bookmark bm = it.next();
				Address addr = bm.getAddress();
				set.addRange(addr, addr);
			}
			return set;
		}

	}

	// for testing
	GTable getBookmarkTable() {
		return provider.getBookmarkTable();
	}
}
