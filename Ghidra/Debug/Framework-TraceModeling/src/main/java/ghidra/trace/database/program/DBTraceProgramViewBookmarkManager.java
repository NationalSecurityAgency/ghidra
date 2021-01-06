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
package ghidra.trace.database.program;

import java.awt.Color;
import java.util.*;
import java.util.function.Predicate;

import javax.swing.ImageIcon;

import org.apache.commons.collections4.IteratorUtils;

import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import generic.NestedIterator;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkType;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.bookmark.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.bookmark.*;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.program.TraceProgramViewBookmarkManager;
import ghidra.util.LockHold;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class DBTraceProgramViewBookmarkManager implements TraceProgramViewBookmarkManager {
	protected static final String[] EMPTY_STRING_ARRAY = new String[0];
	protected static final Bookmark[] EMPTY_BOOKMARK_ARRAY = new Bookmark[0];

	protected final DBTraceProgramView program;
	protected final DBTraceBookmarkManager bookmarkManager;

	public DBTraceProgramViewBookmarkManager(DBTraceProgramView program) {
		this.program = program;
		this.bookmarkManager = program.trace.getBookmarkManager();
	}

	@Override
	public BookmarkType defineType(String type, ImageIcon icon, Color color, int priority) {
		return bookmarkManager.defineBookmarkType(type, icon, color, priority);
	}

	@Override
	public BookmarkType[] getBookmarkTypes() {
		Collection<? extends TraceBookmarkType> types = bookmarkManager.getDefinedBookmarkTypes();
		return types.toArray(new BookmarkType[types.size()]);
	}

	@Override
	public BookmarkType getBookmarkType(String type) {
		return bookmarkManager.getBookmarkType(type);
	}

	@Override
	public String[] getCategories(String type) {
		TraceBookmarkType bmt = bookmarkManager.getBookmarkType(type);
		if (bmt == null) {
			return EMPTY_STRING_ARRAY;
		}
		Collection<String> categories = bmt.getCategories();
		return categories.toArray(new String[categories.size()]);
	}

	@Override
	public Bookmark setBookmark(Address addr, String type, String category, String comment) {
		try (LockHold hold = program.trace.lockWrite()) {
			TraceBookmarkType bmt = bookmarkManager.getOrDefineBookmarkType(type);
			TraceBookmarkSpace space =
				bookmarkManager.getBookmarkSpace(addr.getAddressSpace(), true);
			// TODO: How to let user modify time? I think by deletion at a later snap....
			return space.addBookmark(Range.atLeast(program.snap), addr, bmt, category, comment);
		}
	}

	@Override
	public Bookmark getBookmark(Address addr, String type, String category) {
		try (LockHold hold = program.trace.lockRead()) {
			DBTraceBookmarkSpace space =
				bookmarkManager.getBookmarkSpace(addr.getAddressSpace(), false);
			if (space == null) {
				return null;
			}
			for (long s : program.viewport.getOrderedSnaps()) {
				for (TraceBookmark bm : space.getBookmarksAt(s, addr)) {
					if (!type.equals(bm.getTypeString())) {
						continue;
					}
					if (!category.equals(bm.getCategory())) {
						continue;
					}
					return bm;
				}
			}
			return null;
		}
	}

	protected void doDeleteOrTruncateLifespan(TraceBookmark bm) {
		Range<Long> lifespan = bm.getLifespan();
		if (!lifespan.contains(program.snap)) {
			throw new IllegalArgumentException("Given bookmark is not present at this view's snap");
		}
		if (DBTraceUtils.lowerEndpoint(lifespan) == program.snap) {
			bm.delete();
		}
		else {
			bm.setLifespan(lifespan.intersection(Range.lessThan(program.snap)));
		}
	}

	@Override
	public void removeBookmark(Bookmark bookmark) {
		if (!(bookmark instanceof DBTraceBookmark)) {
			throw new IllegalArgumentException("Given bookmark is not part of this trace");
		}
		DBTraceBookmark dbBookmark = (DBTraceBookmark) bookmark;
		if (dbBookmark.getTrace() != program.trace) {
			throw new IllegalArgumentException("Given bookmark is not part of this trace");
		}
		doDeleteOrTruncateLifespan(dbBookmark);
	}

	@Override
	public void removeBookmarks(String type) {
		try (LockHold hold = program.trace.lockWrite()) {
			for (DBTraceBookmark bm : bookmarkManager.getBookmarksByType(type)) {
				if (!bm.getLifespan().contains(program.snap)) {
					continue;
				}
				doDeleteOrTruncateLifespan(bm);
			}
		}
	}

	@Override
	public void removeBookmarks(String type, String category, TaskMonitor monitor)
			throws CancelledException {
		try (LockHold hold = program.trace.lockWrite()) {
			Collection<DBTraceBookmark> bookmarks = bookmarkManager.getBookmarksByType(type);
			monitor.initialize(bookmarks.size());
			for (DBTraceBookmark bm : bookmarks) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				if (!bm.getLifespan().contains(program.snap)) {
					continue;
				}
				if (!category.equals(bm.getCategory())) {
					continue;
				}
				doDeleteOrTruncateLifespan(bm);
			}
		}
	}

	protected void doRemoveByAddressSet(AddressSetView set, TaskMonitor monitor,
			Predicate<? super TraceBookmark> predicate) throws CancelledException {
		try (LockHold hold = program.trace.lockWrite()) {
			monitor.initialize(set.getNumAddresses());
			for (AddressRange rng : set) {
				monitor.checkCanceled();
				monitor.incrementProgress(rng.getLength());
				DBTraceBookmarkSpace space =
					bookmarkManager.getBookmarkSpace(rng.getAddressSpace(), false);
				if (space == null) {
					continue;
				}
				for (TraceBookmark bm : space.getBookmarksIntersecting(
					Range.closed(program.snap, program.snap), rng)) {
					monitor.checkCanceled();
					if (!bm.getLifespan().contains(program.snap)) {
						continue;
					}
					if (!predicate.test(bm)) {
						continue;
					}
					doDeleteOrTruncateLifespan(bm);
				}
			}
		}
	}

	@Override
	public void removeBookmarks(AddressSetView set, TaskMonitor monitor) throws CancelledException {
		doRemoveByAddressSet(set, monitor, bm -> true);
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, TaskMonitor monitor)
			throws CancelledException {
		// TODO: May want to add two two-field indices to trace bookmark manager:
		//      <Type,Location> and <Location,Type>
		doRemoveByAddressSet(set, monitor, bm -> type.equals(bm.getTypeString()));
	}

	@Override
	public void removeBookmarks(AddressSetView set, String type, String category,
			TaskMonitor monitor) throws CancelledException {
		doRemoveByAddressSet(set, monitor,
			bm -> type.equals(bm.getTypeString()) && category.equals(bm.getCategory()));
	}

	@Override
	public Bookmark[] getBookmarks(Address addr) {
		try (LockHold hold = program.trace.lockRead()) {
			DBTraceBookmarkSpace space =
				bookmarkManager.getBookmarkSpace(addr.getAddressSpace(), false);
			if (space == null) {
				return EMPTY_BOOKMARK_ARRAY;
			}
			List<Bookmark> list = new ArrayList<>();
			for (long s : program.viewport.getOrderedSnaps()) {
				for (TraceBookmark bm : space.getBookmarksAt(s, addr)) {
					if (!bm.getLifespan().contains(program.snap)) {
						continue;
					}
					list.add(bm);
				}
			}
			return list.toArray(new Bookmark[list.size()]);
		}
	}

	@Override
	public Bookmark[] getBookmarks(Address address, String type) {
		try (LockHold hold = program.trace.lockRead()) {
			DBTraceBookmarkSpace space =
				bookmarkManager.getBookmarkSpace(address.getAddressSpace(), false);
			if (space == null) {
				return EMPTY_BOOKMARK_ARRAY;
			}
			List<Bookmark> list = new ArrayList<>();
			for (long s : program.viewport.getOrderedSnaps()) {
				for (TraceBookmark bm : space.getBookmarksAt(s, address)) {
					if (!type.equals(bm.getTypeString())) {
						continue;
					}
					list.add(bm);
				}
			}
			return list.toArray(new Bookmark[list.size()]);
		}
	}

	@Override
	public AddressSetView getBookmarkAddresses(String type) {
		try (LockHold hold = program.trace.lockRead()) {
			// TODO: Implement the interface to be lazy?
			AddressSet result = new AddressSet();
			TraceBookmarkType bmt = bookmarkManager.getBookmarkType(type);
			if (bmt == null) {
				return result;
			}
			for (TraceBookmark bm : bmt.getBookmarks()) {
				if (bm.getAddress().getAddressSpace().isRegisterSpace()) {
					continue;
				}
				if (!program.viewport.containsAnyUpper(bm.getLifespan())) {
					continue;
				}
				result.add(bm.getAddress());
			}
			return result;
		}
	}

	/**
	 * A less restrictive casting of
	 * {@link IteratorUtils#filteredIterator(Iterator, org.apache.commons.collections4.Predicate)}.
	 * 
	 * This one understands that the predicate will be testing things of the (possibly
	 * more-specific) type of elements in the original iterator, not thatof the returned iterator.
	 * 
	 * @param it
	 * @param predicate
	 * @return
	 */
	@SuppressWarnings("unchecked")
	protected static <T, U extends T> Iterator<T> filteredIterator(Iterator<U> it,
			Predicate<? super U> predicate) {
		return (Iterator<T>) Iterators.filter(it, e -> predicate.test(e));
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(String type) {
		TraceBookmarkType bmt = bookmarkManager.getBookmarkType(type);
		if (bmt == null) {
			return Collections.emptyIterator();
		}
		// TODO: May want to offer memory-only and/or register-only bookmark iterators
		return filteredIterator(bmt.getBookmarks().iterator(),
			bm -> !bm.getAddress().getAddressSpace().isRegisterSpace() &&
				program.viewport.containsAnyUpper(bm.getLifespan()));
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator() {
		// TODO: This seems terribly inefficient. We'll have to see how/when it's used.
		return NestedIterator.start(bookmarkManager.getActiveMemorySpaces().iterator(),
			space -> filteredIterator(space.getAllBookmarks().iterator(),
				bm -> program.viewport.containsAnyUpper(bm.getLifespan())));
	}

	protected Comparator<Bookmark> getBookmarkComparator(boolean forward) {
		return forward
				? (b1, b2) -> b1.getAddress().compareTo(b2.getAddress())
				: (b1, b2) -> -b1.getAddress().compareTo(b2.getAddress());
	}

	@Override
	public Iterator<Bookmark> getBookmarksIterator(Address startAddress, boolean forward) {
		AddressFactory factory = program.getAddressFactory();
		AddressSet allMemory = factory.getAddressSet();
		AddressSet within = forward ? factory.getAddressSet(startAddress, allMemory.getMaxAddress())
				: factory.getAddressSet(allMemory.getMinAddress(), startAddress);
		return NestedIterator.start(within.iterator(forward), rng -> {
			DBTraceBookmarkSpace space =
				bookmarkManager.getBookmarkSpace(rng.getAddressSpace(), false);
			if (space == null) {
				return Collections.emptyIterator();
			}
			return program.viewport.mergedIterator(
				s -> space.getBookmarksIntersecting(Range.closed(s, s), rng).iterator(),
				getBookmarkComparator(forward));
		});
	}

	@Override
	public Bookmark getBookmark(long id) {
		TraceBookmark bm = bookmarkManager.getBookmark(id);
		if (bm == null || !bm.getLifespan().contains(program.snap)) {
			return null;
		}
		return bm;
	}

	@Override
	public boolean hasBookmarks(String type) {
		// TODO: Filter by snap?
		// Not really used anywhere, anyway.
		return bookmarkManager.getOrDefineBookmarkType(type).hasBookmarks();
	}

	@Override
	public int getBookmarkCount(String type) {
		// TODO: Filter by snap?
		// Most uses of this are for initializing monitors or as heuristics in analyzers.
		return bookmarkManager.getOrDefineBookmarkType(type).countBookmarks();
	}

	@Override
	public int getBookmarkCount() {
		// TODO: Filter by snap?
		// Not doing so here causes a slight display error in the bookmark table.
		// It will say "Row i of n", but n will be greater than the actual number of rows.
		int sum = 0;
		for (DBTraceBookmarkSpace space : bookmarkManager.getActiveMemorySpaces()) {
			sum += space.getAllBookmarks().size();
		}
		return sum;
	}

	@Override
	public Trace getTrace() {
		return program.trace;
	}

	@Override
	public long getSnap() {
		return program.snap;
	}

	@Override
	public TraceProgramView getProgram() {
		return program;
	}
}
