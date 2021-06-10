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
package ghidra.trace.util;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.google.common.collect.*;

import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.model.DomainObjectException;
import ghidra.program.model.address.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceSnapshotChangeType;
import ghidra.trace.model.TraceDomainObjectListener;
import ghidra.trace.model.program.TraceProgramView;
import ghidra.trace.model.time.*;
import ghidra.util.*;
import ghidra.util.datastruct.ListenerSet;
import ghidra.util.exception.ClosedException;

/**
 * Computes and tracks the "viewport" resulting from forking patterns encoded in snapshot schedules
 * 
 * <p>
 * This is used primarily by the {@link TraceProgramView} implementation to resolve most-recent
 * objects according to a layering or forking structure given in snapshot schedules. This listens on
 * the given trace for changes in snapshot schedules and keeps an up-to-date set of visible (or
 * potentially-visible) ranges from the given snap.
 * 
 * <p>
 * TODO: Because complicated forking structures are not anticipated, some minimal effort is given to
 * cull meaningless changes, but in general, changes cause a complete re-computation of the
 * viewport. If complex, deep forking structures prove to be desirable, then this is an area for
 * optimization.
 */
public class DefaultTraceTimeViewport implements TraceTimeViewport {
	protected class ForSnapshotsListener extends TraceDomainObjectListener
			implements DomainObjectClosedListener {
		{
			listenFor(TraceSnapshotChangeType.ADDED, ignoringClosed(this::snapshotAdded));
			listenFor(TraceSnapshotChangeType.CHANGED, ignoringClosed(this::snapshotChanged));
			listenFor(TraceSnapshotChangeType.DELETED, ignoringClosed(this::snapshotDeleted));
		}

		private AffectedObjectOnlyHandler<? super TraceSnapshot> ignoringClosed(
				AffectedObjectOnlyHandler<? super TraceSnapshot> handler) {
			return snapshot -> {
				try {
					handler.handle(snapshot);
				}
				catch (DomainObjectException e) {
					if (e.getCause() instanceof ClosedException) {
						Msg.warn(this, "Ignoring ClosedException in trace viewport update");
					}
					else {
						throw e;
					}
				}
			};
		}

		private void snapshotAdded(TraceSnapshot snapshot) {
			if (checkSnapshotAddedNeedsRefresh(snapshot)) {
				refreshSnapRanges();
			}
		}

		private void snapshotChanged(TraceSnapshot snapshot) {
			if (checkSnapshotChangedNeedsRefresh(snapshot)) {
				refreshSnapRanges();
			}
		}

		private void snapshotDeleted(TraceSnapshot snapshot) {
			if (checkSnapshotDeletedNeedsRefresh(snapshot)) {
				refreshSnapRanges();
			}
		}

		@Override
		public void domainObjectClosed() {
			trace.removeListener(this);
		}
	}

	protected final Trace trace;
	protected final TraceTimeManager timeManager;
	/**
	 * NB: This is the syncing object for the viewport. If there's even a chance an operation may
	 * need the DB's lock, esp., considering user callbacks, then it must <em>first</em> acquire the
	 * DB lock.
	 */
	protected final List<Range<Long>> ordered = new ArrayList<>();
	protected final RangeSet<Long> spanSet = TreeRangeSet.create();
	protected final ForSnapshotsListener listener = new ForSnapshotsListener();
	protected final ListenerSet<Runnable> changeListeners = new ListenerSet<>(Runnable.class);

	protected long snap;

	public DefaultTraceTimeViewport(Trace trace) {
		this.trace = trace;
		this.timeManager = trace.getTimeManager();
		trace.addCloseListener(listener);
		trace.addListener(listener);
	}

	@Override
	public void addChangeListener(Runnable l) {
		changeListeners.add(l);
	}

	@Override
	public void removeChangeListener(Runnable l) {
		changeListeners.remove(l);
	}

	@Override
	public boolean containsAnyUpper(Range<Long> range) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				// NB. This should only ever visit the first range intersecting that given
				for (Range<Long> intersecting : spanSet.subRangeSet(range).asRanges()) {
					if (range.contains(intersecting.upperEndpoint())) {
						return true;
					}
				}
				return false;
			}
		}
	}

	@Override
	public <T> boolean isCompletelyVisible(AddressRange range, Range<Long> lifespan, T object,
			Occlusion<T> occlusion) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				for (Range<Long> rng : ordered) {
					if (lifespan.contains(rng.upperEndpoint())) {
						return true;
					}
					if (occlusion.occluded(object, range, rng)) {
						return false;
					}
				}
				return false;
			}
		}
	}

	@Override
	public <T> AddressSet computeVisibleParts(AddressSetView set, Range<Long> lifespan, T object,
			Occlusion<T> occlusion) {
		try (LockHold hold = trace.lockRead()) {
			if (!containsAnyUpper(lifespan)) {
				return new AddressSet();
			}
			AddressSet remains = new AddressSet(set);
			synchronized (ordered) {
				for (Range<Long> rng : ordered) {
					if (lifespan.contains(rng.upperEndpoint())) {
						return remains;
					}
					occlusion.remove(object, remains, rng);
					if (remains.isEmpty()) {
						return remains;
					}
				}
			}
		}
		// This condition should have been detected by !containsAnyUpper
		throw new AssertionError();
	}

	protected boolean isLower(long lower) {
		synchronized (ordered) {
			Range<Long> range = spanSet.rangeContaining(lower);
			if (range == null) {
				return false;
			}
			return range.lowerEndpoint().longValue() == lower;
		}
	}

	protected static boolean addSnapRange(long lower, long upper, RangeSet<Long> spanSet,
			List<Range<Long>> ordered) {
		if (spanSet.contains(lower)) {
			return false;
		}
		Range<Long> range = Range.closed(lower, upper);
		spanSet.add(range);
		ordered.add(range);
		return true;
	}

	protected static TraceSnapshot locateMostRecentFork(TraceTimeManager timeManager, long from) {
		while (true) {
			TraceSnapshot prev = timeManager.getMostRecentSnapshot(from);
			if (prev == null) {
				return null;
			}
			TraceSchedule prevSched = prev.getSchedule();
			long prevKey = prev.getKey();
			if (prevSched == null) {
				if (prevKey == Long.MIN_VALUE) {
					return null;
				}
				from = prevKey - 1;
				continue;
			}
			long forkedSnap = prevSched.getSnap();
			if (forkedSnap == prevKey - 1) {
				// Schedule is notational without forking
				from--;
				continue;
			}
			return prev;
		}
	}

	/**
	 * Construct the ranges (set and ordered)
	 * 
	 * <p>
	 * NOTE: I cannot hold the lock during this, because I also require the DB's read lock. There
	 * are other operations, e.g., addRegion, that will hold the DB's write lock, and then also
	 * require the viewport's lock to check if it is visible. That would cause the classic tango of
	 * death.
	 * 
	 * @param curSnap the seed snap
	 */
	protected static void collectForkRanges(TraceTimeManager timeManager, long curSnap,
			RangeSet<Long> spanSet, List<Range<Long>> ordered) {
		while (true) {
			TraceSnapshot fork = locateMostRecentFork(timeManager, curSnap);
			long prevSnap = fork == null ? Long.MIN_VALUE : fork.getKey();
			if (!addSnapRange(prevSnap, curSnap, spanSet, ordered)) {
				return;
			}
			if (fork == null) {
				return;
			}
			curSnap = fork.getSchedule().getSnap();
		}
	}

	protected void refreshSnapRanges() {
		RangeSet<Long> spanSet = TreeRangeSet.create();
		List<Range<Long>> ordered = new ArrayList<>();
		try (LockHold hold = trace.lockRead()) {
			collectForkRanges(timeManager, snap, spanSet, ordered);
		}
		synchronized (this.ordered) {
			this.spanSet.clear();
			this.ordered.clear();
			this.spanSet.addAll(spanSet);
			this.ordered.addAll(ordered);
		}
		assert !ordered.isEmpty();
		changeListeners.fire.run();
	}

	public void setSnap(long snap) {
		this.snap = snap;
		refreshSnapRanges();
	}

	protected boolean checkSnapshotAddedNeedsRefresh(TraceSnapshot snapshot) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				if (snapshot.getSchedule() == null) {
					return false;
				}
				if (spanSet.contains(snapshot.getKey())) {
					return true;
				}
				return false;
			}
		}
	}

	protected boolean checkSnapshotChangedNeedsRefresh(TraceSnapshot snapshot) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				if (isLower(snapshot.getKey())) {
					return true;
				}
				if (spanSet.contains(snapshot.getKey()) && snapshot.getSchedule() != null) {
					return true;
				}
				return false;
			}
		}
	}

	protected boolean checkSnapshotDeletedNeedsRefresh(TraceSnapshot snapshot) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				if (isLower(snapshot.getKey())) {
					return true;
				}
				return false;
			}
		}
	}

	@Override
	public boolean isForked() {
		synchronized (ordered) {
			return ordered.size() > 1;
		}
	}

	@Override
	public List<Long> getOrderedSnaps() {
		synchronized (ordered) {
			return ordered
					.stream()
					.map(Range::upperEndpoint)
					.collect(Collectors.toList());
		}
	}

	@Override
	public List<Long> getReversedSnaps() {
		synchronized (ordered) {
			return Lists.reverse(ordered)
					.stream()
					.map(Range::upperEndpoint)
					.collect(Collectors.toList());
		}
	}

	@Override
	public <T> T getTop(Function<Long, T> func) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				for (Range<Long> rng : ordered) {
					T t = func.apply(rng.upperEndpoint());
					if (t != null) {
						return t;
					}
				}
				return null;
			}
		}
	}

	@Override
	public <T> Iterator<T> mergedIterator(Function<Long, Iterator<T>> iterFunc,
			Comparator<? super T> comparator) {
		List<Iterator<T>> iters;
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				if (!isForked()) {
					return iterFunc.apply(snap);
				}
				iters = ordered.stream()
						.map(rng -> iterFunc.apply(rng.upperEndpoint()))
						.collect(Collectors.toList());
			}
		}
		return new UniqIterator<>(new MergeSortingIterator<>(iters, comparator));
	}

	@Override
	public AddressSetView unionedAddresses(Function<Long, AddressSetView> viewFunc) {
		List<AddressSetView> views;
		try (LockHold hold = trace.lockRead()) {
			synchronized (ordered) {
				if (!isForked()) {
					return viewFunc.apply(snap);
				}
				views = ordered.stream()
						.map(rng -> viewFunc.apply(rng.upperEndpoint()))
						.collect(Collectors.toList());
			}
		}
		return new UnionAddressSetView(views);
	}
}
