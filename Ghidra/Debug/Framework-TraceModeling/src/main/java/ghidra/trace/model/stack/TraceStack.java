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
package ghidra.trace.model.stack;

import java.util.List;

import ghidra.trace.model.thread.TraceThread;

/**
 * A trace of the connected debugger's stack unwind
 * 
 * Most of the information stored here is ancillary, since with sufficient analysis of associated
 * images, it could be recovered, in the same fashion as the connected debugger did. Nevertheless,
 * during a debug session, this information should be recorded if offered, as it makes it
 * immediately accessible, before sufficient analysis has been performed, and provides some check
 * for that analysis. If this information wasn't recorded during a session, this can store the
 * result of that analysis.
 */
public interface TraceStack {

	/**
	 * Get the thread whose stack this is
	 * 
	 * @return the thread
	 */
	TraceThread getThread();

	/**
	 * Get the snap where this stack is certain
	 * 
	 * @return the snap
	 */
	long getSnap();

	/**
	 * Get the depth (as recorded) of this stack
	 * 
	 * @return the depth
	 */
	int getDepth();

	/**
	 * Set the depth of the stack by adding or deleting frames to or from the specified end
	 * 
	 * Note that pushing new frames onto a stack does not adjust the frame level of any associated
	 * annotations. Some utility to adjust those annotations. Cannot just rename tables, since those
	 * contain annotations for the given level, regardless of the particular stack.
	 * 
	 * @param depth the desired depth
	 * @param atInner true if frames should be "pushed"
	 */
	void setDepth(int depth, boolean atInner);

	/**
	 * Get the frame at the given level
	 * 
	 * @param level the level, where 0 indicates the inner-most frame.
	 * @param ensureDepth true to expand the depth to accomodate the requested frame
	 * @return the frame, or {@code null} if level exceeds the depth without ensureDepth set
	 * @throws IndexOutOfBoundsException if the level is negative
	 */
	TraceStackFrame getFrame(int level, boolean ensureDepth);

	/**
	 * Get all (known) frames in this stack
	 * 
	 * @return the list of frames
	 */
	List<TraceStackFrame> getFrames();

	/**
	 * Delete this stack and its frames
	 */
	void delete();
}
