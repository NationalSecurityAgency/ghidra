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

import ghidra.trace.model.Trace;
import ghidra.trace.model.thread.TraceThread;

/**
 * A "snapshot in time" in a trace
 *
 * This is not so much a snapshot as it is simply a marker in time. Each manager handles time on its
 * own, using the keys from these snapshots. Snapshot keys are called "snaps" for short. While a
 * snapshot need not exist for another manager to use its numeric key, it is proper convention to
 * create a snapshot before populating any other manager with corresponding entries.
 * 
 * NOTE: There is a transitional phase here where some managers may still use "tick" instead of
 * "snap".
 */
public interface TraceSnapshot {
	Trace getTrace();

	/**
	 * Get a key which orders the snapshot chronologically
	 * 
	 * @return the database key
	 */
	long getKey();

	/**
	 * Get the description of the snapshot
	 * 
	 * @return
	 */
	String getDescription();

	/**
	 * Set the human-consumable description of the snapshot
	 * 
	 * @param description the description
	 */
	void setDescription(String description);

	/**
	 * Get the real creation time of this snapshot in milliseconds since the epoch
	 * 
	 * @return the real time
	 */
	long getRealTime();

	/**
	 * Set the real creation time of this snapshot in milliseconds since Jan 1, 1970 12:00 AM (UTC)
	 * 
	 * @param millisSinceEpoch the real time
	 */
	void setRealTime(long millisSinceEpoch);

	/**
	 * If this snapshot was created because of an event, get the thread that caused it
	 * 
	 * @return the event thread, if applicable
	 */
	TraceThread getEventThread();

	/**
	 * If this snapshot was create because of an event, set the thread that caused it
	 * 
	 * @param thread the event thread, if applicable
	 */
	void setEventThread(TraceThread thread);

	/**
	 * Get the schedule, if applicable and known, relating this snapshot to a previous one
	 * 
	 * <p>
	 * This information is not always known, or even applicable. If recording a single step,
	 * ideally, this is simply the previous snap plus one step of the event thread, e.g., for snap
	 * 6, the schedule would be "5:1". For an emulated machine cached in scratch space, this should
	 * be the schedule that would recover the same machine state.
	 * 
	 * <p>
	 * The object managers in the trace pay no heed to this schedule. In particular, when retrieving
	 * the "most-recent" information from a snapshot with a known schedule, the "previous snap" part
	 * of that schedule is <em>not</em> taken into account. In other words, the managers still
	 * interpret time linearly, even though this schedule field might imply built-in forking.
	 * 
	 * @return the (possibly null) schedule
	 */
	TraceSchedule getSchedule();

	/**
	 * Get the string representation of the schedule
	 * 
	 * @return the (possibly empty) string representation of the schedule
	 */
	String getScheduleString();

	/**
	 * Set the schedule from some previous snapshot to this one
	 * 
	 * @param schedule the schedule
	 */
	void setSchedule(TraceSchedule schedule);

	/**
	 * Delete this snapshot
	 * 
	 * This does not delete any entries in other managers associated with this snapshot. This simply
	 * deletes the marker and accompanying metadata. However, entries associated with deleted or
	 * otherwise non-existent snapshot keys may cause interesting behavior, especially for keys
	 * which exceed the latest snapshot key.
	 */
	void delete();
}
