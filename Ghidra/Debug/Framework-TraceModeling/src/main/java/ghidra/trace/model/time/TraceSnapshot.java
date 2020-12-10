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
	 * Get the number of ticks, if known, between this snapshot and the next
	 * 
	 * @return the (unsigned) number of ticks, or 0 for unspecified.
	 */
	long getTicks();

	/**
	 * Set the number of ticks between this snapshot and the next
	 * 
	 * Conventionally, 0 indicates unknown or unspecified
	 * 
	 * @param ticks the number of ticks
	 */
	void setTicks(long ticks);

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
