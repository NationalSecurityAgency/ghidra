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

import com.google.common.collect.Range;

import ghidra.lifecycle.Experimental;
import ghidra.program.model.address.Address;

/**
 * A frame in a {@link TraceStack}
 */
public interface TraceStackFrame {
	/**
	 * Get the containing stack
	 * 
	 * @return the stack
	 */
	TraceStack getStack();

	/**
	 * Get the frame's position in the containing stack
	 * 
	 * <p>
	 * 0 represents the innermost frame or top of the stack.
	 * 
	 * @return the frame's level
	 */
	int getLevel();

	/**
	 * Get the program counter at the given snap
	 * 
	 * @param snap the snap (only relevant in the experimental objects mode. Ordinarily, the PC is
	 *            fixed over the containing stack's lifetime)
	 * @return the program counter
	 */
	Address getProgramCounter(@Experimental long snap);

	/**
	 * Set the program counter over the given span
	 * 
	 * @param span the span (only relevant in the experimental objects mode. Ordinarily, the PC is
	 *            fixed over the containing stack's lifetime)
	 * @param pc the program counter
	 */
	void setProgramCounter(@Experimental Range<Long> span, Address pc);

	/**
	 * Get the user comment for the frame
	 * 
	 * <p>
	 * In the experimental objects mode, this actually gets the comment in the listing at the
	 * frame's program counter for the given snap.
	 * 
	 * @param snap the snap (only relevant in the experimental objects mode)
	 * @return the (nullable) comment
	 */
	String getComment(@Experimental long snap);

	/**
	 * Set the user comment for the frame
	 * 
	 * <p>
	 * In the experimental objects mode, this actually sets the comment in the listing at the
	 * frame's program counter for the given snap.
	 * 
	 * @param snap the snap (only relevant in the experimental objects mode)
	 * @param comment the (nullable) comment
	 */
	void setComment(@Experimental long snap, String comment);
}
