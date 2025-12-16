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

import ghidra.program.model.lang.Register;
import ghidra.trace.model.*;
import ghidra.trace.model.target.iface.TraceExecutionStateful;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInfo;

/**
 * A thread in a trace
 * 
 * <p>
 * This object must be associated with a suitable {@link TraceExecutionStateful}. In most
 * cases, the object should just implement it.
 */
@TraceObjectInfo(
	schemaName = "Thread",
	shortName = "thread",
	attributes = {
		TraceThread.KEY_TID,
	},
	fixedKeys = {
		TraceObjectInterface.KEY_DISPLAY,
		TraceObjectInterface.KEY_COMMENT,
	})
public interface TraceThread extends TraceUniqueObject, TraceObjectInterface {
	/** The key that gives the TID, as assigned by the target's platform */
	String KEY_TID = "_tid";

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
	 * @param snap the snap
	 * @return the name
	 */
	String getName(long snap);

	/**
	 * Set the "short name" of this thread
	 * 
	 * @param lifespan the span of time
	 * @param name the name
	 */
	void setName(Lifespan lifespan, String name);

	/**
	 * Set the "short name" of this thread
	 * 
	 * @param snap the starting snap
	 * @param name the name
	 */
	void setName(long snap, String name);

	/**
	 * Set a comment on this thread
	 * 
	 * @param snap the snap
	 * @param comment the comment, possibly {@code null}
	 */
	void setComment(long snap, String comment);

	/***
	 * Get the comment on this thread
	 * 
	 * @param snap the snap
	 * @return the comment, possibly {@code null}
	 */
	String getComment(long snap);

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

	/**
	 * Remove this thread from the given snapshot on
	 * 
	 * @param snap the snapshot key
	 */
	void remove(long snap);

	/**
	 * Check if the thread is valid at the given snapshot
	 * 
	 * <p>
	 * In object mode, a thread's life may be disjoint, so checking if the snap occurs between
	 * creation and destruction is not quite sufficient. This method encapsulates validity. In
	 * object mode, it checks that the thread object has a canonical parent at the given snapshot.
	 * In table mode, it checks that the lifespan contains the snap.
	 * 
	 * @param snap the snapshot key
	 * @return true if valid, false if not
	 */
	boolean isValid(long snap);

	/**
	 * Check if the module is alive for any of the given span
	 * 
	 * @param span the span
	 * @return true if its life intersects the span
	 */
	boolean isAlive(Lifespan span);
}
