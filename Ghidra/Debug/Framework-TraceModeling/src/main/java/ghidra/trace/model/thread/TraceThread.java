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
package ghidra.trace.model.thread;

import java.util.List;

import com.google.common.collect.Range;

import ghidra.program.model.lang.Register;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceObject;
import ghidra.util.exception.DuplicateNameException;

/**
 * A thread in a trace
 */
public interface TraceThread extends TraceObject {

	/**
	 * Get the trace containing this thread
	 * 
	 * @return the trace
	 */
	Trace getTrace();

	/**
	 * Get a key identifying this thread, unique among all threads in this trace for all time
	 * 
	 * @return the key
	 */
	long getKey();

	/**
	 * Get the "full name" of this thread
	 * 
	 * @return the path
	 */
	String getPath();

	/**
	 * Get the "short name" of this thread
	 * 
	 * @return the name
	 */
	String getName();

	/**
	 * Set the "short name" of this thread
	 * 
	 * @param name the name
	 */
	void setName(String name);

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param creationSnap the creation snap, or {@link Long#MIN_VALUE} for "since the beginning of
	 *            time"
	 */
	void setCreationSnap(long creationSnap) throws DuplicateNameException;

	/**
	 * Get the creation snap of this thread
	 * 
	 * @return the creation snap, or {@link Long#MIN_VALUE} for "since the beginning of time"
	 */
	long getCreationSnap();

	/**
	 * @see #setLifespan(Range)
	 * 
	 * @param destructionSnap the destruction snap, or {@link Long#MAX_VALUE} for "to the end of
	 *            time"
	 */
	void setDestructionSnap(long destructionSnap) throws DuplicateNameException;

	/**
	 * Get the destruction snap of this thread
	 * 
	 * @return the destruction snap, or {@link Long#MAX_VALUE} for "to the end of time"
	 */
	long getDestructionSnap();

	/**
	 * Set the lifespan of this thread
	 * 
	 * @param lifespan the lifespan
	 * @throws DuplicateNameException if the specified lifespan would cause the full name of this
	 *             thread to conflict with that of another whose lifespan would intersect this
	 *             thread's
	 */
	void setLifespan(Range<Long> lifespan) throws DuplicateNameException;

	/**
	 * Get the lifespan of this thread
	 * 
	 * @return the lifespan
	 */
	Range<Long> getLifespan();

	/**
	 * Set a comment on this thread
	 * 
	 * @param comment the comment, possibly {@code null}
	 */
	void setComment(String comment);

	/***
	 * Get the comment on this thread
	 * 
	 * @return the comment, possibly {@code null}
	 */
	String getComment();

	/**
	 * Check if the thread has a recorded destruction snap
	 * 
	 * @return false if destroyed, true otherwise
	 */
	default boolean isAlive() {
		return !getLifespan().hasUpperBound();
	}

	/**
	 * A convenience to obtain the registers from the containing trace's base language
	 * 
	 * @return the list of registers
	 */
	default List<Register> getRegisters() {
		return getTrace().getBaseLanguage().getRegisters();
	}

	/**
	 * Delete this thread from the trace
	 */
	void delete();
}
