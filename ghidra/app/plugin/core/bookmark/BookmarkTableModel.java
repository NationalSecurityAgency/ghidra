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

import java.util.*;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.LongIterator;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.*;
import ghidra.util.task.TaskMonitor;

class BookmarkTableModel extends AddressBasedTableModel<BookmarkRowObject> {

	final static int TYPE_COL = 0;
	final static int CATEGORY_COL = 1;
	final static int COMMENT_COL = 2;
	final static int LOCATION_COL = 3;
	final static int LABEL_COL = 4;
	final static int PREVIEW_COL = 5;

	private BookmarkManager bookmarkMgr;
	private Bookmark lastBookmark;
	private Set<String> types = new HashSet<>();
	private PluginTool tool;

	BookmarkTableModel(PluginTool tool, Program program) {
		super("Bookmarks", tool, program, null);
		this.tool = tool;

		initialize(program);
	}

	@Override
	protected TableColumnDescriptor<BookmarkRowObject> createTableColumnDescriptor() {
		TableColumnDescriptor<BookmarkRowObject> descriptor = new TableColumnDescriptor<>();

		descriptor.addVisibleColumn(new TypeTableColumn(), 1, true);
		descriptor.addVisibleColumn(new CategoryTableColumn());
		descriptor.addVisibleColumn(new DescriptionTableColumn());
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new LabelTableColumn()));
		descriptor.addVisibleColumn(
			DiscoverableTableUtils.adaptColumForModel(this, new CodeUnitTableColumn()));

		return descriptor;
	}

	int getKeyCount() {
		if (bookmarkMgr == null) {
			return 0;
		}
		return bookmarkMgr.getBookmarkCount();
	}

	private int getIteratorKeyCount() {
		if (bookmarkMgr == null) {
			return 0;
		}
		int cnt = 0;
		Iterator<String> it = types.iterator();
		while (it.hasNext()) {
			String type = it.next();
			cnt += bookmarkMgr.getBookmarkCount(type);
		}
		return cnt;
	}

	@Override
	protected void doLoad(Accumulator<BookmarkRowObject> accumulator, TaskMonitor monitor)
			throws CancelledException {
		LongIterator it = LongIterator.EMPTY;
		if (bookmarkMgr != null && !types.isEmpty()) {
			it = new BookmarkKeyIterator(bookmarkMgr);
		}
		monitor.initialize(getIteratorKeyCount());
		int i = 0;
		while (it.hasNext()) {
			monitor.checkCanceled();
			monitor.setProgress(i++);
			long key = it.next();
			accumulator.add(new BookmarkRowObject(key));
		}
	}

	boolean hasTypeFilterApplied() {
		if (bookmarkMgr == null) {
			return false;
		}

		BookmarkType[] programTypes = bookmarkMgr.getBookmarkTypes();
		int allKnowTypesSize = programTypes.length;
		return !types.isEmpty() && types.size() != allKnowTypesSize;
	}

	FilterState getFilterState() {
		return new FilterState(new HashSet<>(types));
	}

	void restoreFilterState(FilterState filterState) {
		Set<String> newTypes = filterState.getBookmarkTypes();
		types = newTypes;
	}

	private void adjustTypeFilter(BookmarkType[] bmTypes) {
		Set<String> defaultTypesSet = new HashSet<>();
		for (BookmarkType element : bmTypes) {
			defaultTypesSet.add(element.getTypeString());
		}

		if (types.isEmpty()) {
			// no pre-existing types; use the program's types
			types = defaultTypesSet;
		}
		else {
			// only show those that are already enabled; if they are not in 'types', then they 
			// will be disabled
			types.retainAll(defaultTypesSet);
		}
	}

	void bookmarkAdded(Bookmark bookmark) {
		if (isShowingType(bookmark.getTypeString())) {
			long key = bookmark.getId();
			addObject(new BookmarkRowObject(key));
		}
	}

	void bookmarkChanged(Bookmark bookmark) {
		if (isShowingType(bookmark.getTypeString())) {
			long key = bookmark.getId();
			updateObject(new BookmarkRowObject(key));
		}
	}

	void bookmarkRemoved(Bookmark bookmark) {
		if (isShowingType(bookmark.getTypeString())) {
			long key = bookmark.getId();
			removeObject(new BookmarkRowObject(key));
		}
	}

	Collection<String> getAllTypes() {
		return Collections.unmodifiableCollection(types);
	}

	void showType(String type) {
		types.add(type);
	}

	boolean isShowingType(String type) {
		return types.contains(type);
	}

	void hideAllTypes() {
		types.clear();
	}

	public void typeAdded() {
		initialize(program);
	}

	Bookmark getBookmark(long key) {
		return bookmarkMgr.getBookmark(key);
	}

	void reload(Program newProgram) {
		setProgram(newProgram);
		initialize(getProgram());
		reload();
	}

	private void initialize(Program newProgram) {
		if (newProgram == null) {
			bookmarkMgr = null;

			// keep the types around between programs; they represent all known, visible 
			// bookmarks, which we want to use as the user toggles between open programs
			// types = new HashSet<>();
			return;
		}

		bookmarkMgr = newProgram.getBookmarkManager();
		BookmarkType[] bmTypes = bookmarkMgr.getBookmarkTypes();
		adjustTypeFilter(bmTypes);
	}

	@Override
	public boolean isCellEditable(int row, int columnIndex) {
		return (columnIndex == CATEGORY_COL || columnIndex == COMMENT_COL);
	}

	@Override
	public void setValueAt(Object aValue, int row, int columnIndex) {
		if (row < 0 || row >= filteredData.size()) {
			return;
		}
		BookmarkRowObject rowObject = filteredData.get(row);
		Bookmark bm = getBookmarkForRowObject(rowObject);

		if (bm == null) {
			return;
		}
		switch (columnIndex) {
			case CATEGORY_COL:
				tool.execute(new BookmarkEditCmd(bm, (String) aValue, bm.getComment()),
					getProgram());
				break;
			case COMMENT_COL:
				tool.execute(new BookmarkEditCmd(bm, bm.getCategory(), (String) aValue),
					getProgram());
				break;
		}

	}

	@Override
	public Address getAddress(int row) {
		Bookmark bookmark = getBookmarkForRowObject(getRowObject(row));
		return bookmark != null ? bookmark.getAddress() : null;
	}

	private Bookmark getBookmarkForRowObject(BookmarkRowObject storageObject) {
		if (getProgram() == null) {
			return null;
		}

		long key = storageObject.getKey();
		if (lastBookmark == null || lastBookmark.getId() != key) {
			lastBookmark = bookmarkMgr.getBookmark(key);
		}
		return lastBookmark;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class BookmarkKeyIterator implements LongIterator {
		private int nextIter = 1;
		private List<Iterator<Bookmark>> iters = new ArrayList<>();
		private Iterator<Bookmark> currIter;

		BookmarkKeyIterator(BookmarkManager bookmarkMgr) {
			Iterator<String> it = types.iterator();
			while (it.hasNext()) {
				String type = it.next();
				Iterator<Bookmark> bkIt = bookmarkMgr.getBookmarksIterator(type);
				if (bkIt.hasNext()) {
					iters.add(bkIt);
				}
			}
			if (iters.size() > 0) {
				currIter = iters.get(0);
			}
		}

		/**
		 * @see ghidra.util.LongIterator#hasNext()
		 */
		@Override
		public boolean hasNext() {
			if (currIter == null) {
				return false;
			}
			return currIter.hasNext() || nextIter < iters.size();
		}

		/**
		 * @see ghidra.util.LongIterator#next()
		 */
		@Override
		public long next() {
			if (!currIter.hasNext()) {
				currIter = iters.get(nextIter++);
			}
			Bookmark bookmark = currIter.next();
			return bookmark.getId();
		}

		/**
		 * @see ghidra.util.LongIterator#hasPrevious()
		 */
		@Override
		public boolean hasPrevious() {
			throw new UnsupportedOperationException();
		}

		/**
		 * @see ghidra.util.LongIterator#previous()
		 */
		@Override
		public long previous() {
			throw new UnsupportedOperationException();
		}
	}

	private class TypeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BookmarkRowObject, String> {

		@Override
		public String getColumnDisplayName(Settings settings) {
			return getColumnName();
		}

		@Override
		public String getColumnName() {
			return "Type";
		}

		@Override
		public String getValue(BookmarkRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Bookmark bookmark = getBookmarkForRowObject(rowObject);
			if (bookmark == null) {
				return null;
			}
			return bookmark.getTypeString();
		}
	}

	private class CategoryTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BookmarkRowObject, String> {

		@Override
		public String getColumnName() {
			return "Category";
		}

		@Override
		public String getValue(BookmarkRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Bookmark bookmark = getBookmarkForRowObject(rowObject);
			if (bookmark == null) {
				return null;
			}
			return bookmark.getCategory();
		}
	}

	private class DescriptionTableColumn
			extends AbstractProgramBasedDynamicTableColumn<BookmarkRowObject, String> {

		@Override
		public String getColumnName() {
			return "Description";
		}

		@Override
		public String getValue(BookmarkRowObject rowObject, Settings settings, Program p,
				ServiceProvider provider) throws IllegalArgumentException {
			Bookmark bookmark = getBookmarkForRowObject(rowObject);
			if (bookmark == null) {
				return null;
			}
			return bookmark.getComment();
		}
	}
}
