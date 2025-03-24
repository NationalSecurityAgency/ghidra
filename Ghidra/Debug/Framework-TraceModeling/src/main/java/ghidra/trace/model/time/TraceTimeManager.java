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
package ghidra.trace.model.time;

import java.util.Collection;

import ghidra.trace.model.time.schedule.TraceSchedule;

public interface TraceTimeManager {
	/**
	 * Create a new snapshot after the latest
	 * 
	 * @param description a description of the new snapshot, i.e., the reason for advancing
	 * @return the created snapshot
	 */
	TraceSnapshot createSnapshot(String description);

	/**
	 * Get the snapshot with the given key, optionally creating it
	 * 
	 * @param snap the snapshot key
	 * @return the snapshot or {@code null}
	 */
	TraceSnapshot getSnapshot(long snap, boolean createIfAbsent);

	/**
	 * Get the most recent snapshot since a given key
	 * 
	 * @param snap the snapshot key
	 * @return the snapshot or {@code null}
	 */
	TraceSnapshot getMostRecentSnapshot(long snap);

	/**
	 * Get all snapshots with the given schedule
	 * 
	 * <p>
	 * Ideally, the snapshot schedules should be managed such that the returned collection contains
	 * at most one snapshot.
	 * 
	 * @param schedule the schedule to find
	 * @return the snapshots
	 */
	Collection<? extends TraceSnapshot> getSnapshotsWithSchedule(TraceSchedule schedule);

	/**
	 * Find or create a the snapshot with the given schedule
	 * 
	 * <p>
	 * If a snapshot with the given schedule already exists, this returns the first such snapshot
	 * found. Ideally, there is exactly one. If this method is consistently used for creating
	 * scratch snapshots, then that should always be the case. If no such snapshot exists, this
	 * creates a snapshot with the minimum available negative snapshot key, that is starting at
	 * {@link Long#MIN_VALUE} and increasing from there.
	 * 
	 * @param schedule the schedule to find
	 * @return the snapshot
	 */
	TraceSnapshot findScratchSnapshot(TraceSchedule schedule);

	/**
	 * List all snapshots in the trace
	 * 
	 * @return the set of snapshots
	 */
	Collection<? extends TraceSnapshot> getAllSnapshots();

	/**
	 * List all snapshots between two given snaps in the trace
	 * 
	 * @param fromSnap the starting snap
	 * @param fromInclusive whether to include the from snap
	 * @param toSnap the ending snap
	 * @param toInclusive when to include the to snap
	 * @return the set of snapshots
	 */
	Collection<? extends TraceSnapshot> getSnapshots(long fromSnap, boolean fromInclusive,
			long toSnap, boolean toInclusive);

	/**
	 * Get maximum snapshot key that has ever existed, usually that of the latest snapshot
	 * 
	 * Note, the corresponding snapshot need not exist, as it may have been deleted.
	 * 
	 * @return the key, or {@code null} if no snapshots have existed
	 */
	Long getMaxSnap();

	/**
	 * Get the number of snapshots
	 * 
	 * @return the count
	 */
	long getSnapshotCount();
}
