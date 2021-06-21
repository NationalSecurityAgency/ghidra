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
package ghidra.dbg;

import java.util.*;

import ghidra.dbg.error.DebuggerMemoryAccessException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetConsole.Channel;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.util.Msg;

/**
 * A listener for events related to the debugger model, including its connection and objects
 */
public interface DebuggerModelListener {

	/**
	 * An error occurred such that this listener will no longer receive events
	 * 
	 * @param t the exception describing the error
	 */
	default public void catastrophic(Throwable t) {
		Msg.error(this, "Catastrophic listener error", t);
	}

	/**
	 * The model has been successfully opened
	 * 
	 * <p>
	 * For example, the connection to a debugger daemon has been established and negotiated.
	 */
	default public void modelOpened() {
	}

	/**
	 * The model's state has changed, prompting an update to its description
	 */
	default public void modelStateChanged() {
	}

	/**
	 * The model was closed
	 * 
	 * <p>
	 * For example, the remote closed the connection, or the connection was lost. Whatever the case,
	 * the model is invalid after this callback.
	 * 
	 * @param reason the reason for the model to close
	 */
	default public void modelClosed(DebuggerModelClosedReason reason) {
	}

	/**
	 * An object was created
	 * 
	 * <p>
	 * This can only be received by listening on the model. While the created object can now appear
	 * in other callbacks, it should not be used aside from those callbacks, until it is added to
	 * the model. Until that time, the object may not adhere to the schema, since its children are
	 * still being initialized.
	 * 
	 * @param object the newly-created object
	 */
	default void created(TargetObject object) {
	}

	/**
	 * An object is no longer valid
	 * 
	 * <p>
	 * This should be the final callback ever issued for this object. Invalidation of an object
	 * implies invalidation of all its successors; nevertheless, the implementation MUST explicitly
	 * invoke this callback for those successors in preorder. Users need only listen for
	 * invalidation by installing a listener on the object of interest. However, a user must be able
	 * to ignore invalidation events on an object it has already removed and/or invalidated. The
	 * {@code branch} parameter will identify the branch node of the sub-tree being removed. For
	 * models that are managed by a client connection, disconnecting or otherwise terminating the
	 * session should invalidate the root, and thus every object must receive this callback.
	 * 
	 * <p>
	 * If an invalidated object is replaced (i.e., a new object with the same path is added to the
	 * model), the implementation must be careful to issue all invalidations related to the removed
	 * object before the replacement is added, so that delayed invalidations are not mistakenly
	 * applied to the replacement or its successors.
	 * 
	 * @param object the now-invalid object
	 * @param branch the root of the sub-tree being invalidated
	 * @param reason an informational, human-consumable reason, if applicable
	 */
	default void invalidated(TargetObject object, TargetObject branch, String reason) {
	}

	/**
	 * The root object has been added to the model
	 * 
	 * <p>
	 * This indicates the root is ready, not just {@link #created(TargetObject)}. Note this callback
	 * indicates the root being "added to the model."
	 * 
	 * @param root the root object
	 */
	default public void rootAdded(TargetObject root) {
	}

	/**
	 * The object's elements changed
	 * 
	 * <p>
	 * The listener must have received a prior {@link #created(TargetObject)} callback for the
	 * parent and all (object-valued) elements being added. Assuming {@code object} has already been
	 * "added the model," this callback indicates all objects in the {@code added} parameter being
	 * "added to the model" along with their successors.
	 * 
	 * @param object the object whose children changed
	 * @param removed the list of removed children
	 * @param added a map of indices to new children references
	 */
	default void elementsChanged(TargetObject object, Collection<String> removed,
			Map<String, ? extends TargetObject> added) {
	}

	/**
	 * The object's attributes changed
	 * 
	 * <p>
	 * In the case of an object-valued attribute, changes to that object do not constitute a changed
	 * attribute. The attribute is considered changed only when that attribute is assigned to a
	 * completely different object.
	 * 
	 * @param object the object whose attributes changed
	 * @param removed the list of removed attributes
	 * @param added a map of names to new/changed attributes
	 */
	default void attributesChanged(TargetObject object, Collection<String> removed,
			Map<String, ?> added) {
	}

	/**
	 * The model has requested the client invalidate (non-tree) caches associated with an object
	 * 
	 * <p>
	 * For objects with methods exposing contents other than elements and attributes (e.g., memory
	 * and register contents), this callback requests that any caches associated with that content
	 * be invalidated. Most notably, this usually occurs when an object (e.g., thread) enters the
	 * {@link TargetExecutionState#RUNNING} state, to inform proxies that they should invalidate
	 * their memory and register caches. In most cases, clients need not worry about this callback.
	 * Protocol implementations that use the model, however, should forward this request to the
	 * client-side peer.
	 * 
	 * <p>
	 * Note caches of elements and attributes are not affected by this callback. See
	 * {@link TargetObject#invalidateCaches()}.
	 * 
	 * @param object the object whose caches must be invalidated
	 */
	default void invalidateCacheRequested(TargetObject object) {
	}

	/**
	 * A breakpoint trapped execution
	 * 
	 * <p>
	 * The program counter can be obtained in a few ways. The most reliable is to get the address of
	 * the breakpoint location. If available, the frame will also contain the program counter.
	 * Finally, the trapped object or one of its relatives may offer the program counter.
	 * 
	 * @param container the container whose breakpoint trapped execution
	 * @param trapped the object whose execution was trapped, usually a {@link TargetThread}
	 * @param frame the innermost stack frame, if available, of the trapped object
	 * @param spec the breakpoint specification
	 * @param breakpoint the breakpoint location that actually trapped execution
	 */
	default void breakpointHit(TargetObject container, TargetObject trapped,
			TargetStackFrame frame, TargetBreakpointSpec spec,
			TargetBreakpointLocation breakpoint) {
	}

	/**
	 * A console has produced output (given as bytes)
	 * 
	 * <p>
	 * Note that "captured" outputs will not be reported in this callback. See
	 * {@link TargetInterpreter#executeCapture(String)}.
	 * 
	 * @param console the console producing the output
	 * @param channel identifies the "output stream", stdout or stderr
	 * @param data the output data
	 */
	default void consoleOutput(TargetObject console, Channel channel, byte[] data) {
	}

	/**
	 * A console has produced output (given as a string)
	 * 
	 * @implNote Overriding this method is not a substitute for overriding
	 *           {@link #consoleOutput(TargetObject, Channel, byte[])}. Some models may invoke this
	 *           {@code String} variant as a convenience, which by default, invokes the
	 *           {@code byte[]} variant, but models are only expected to invoke the {@code byte[]}
	 *           variant. A client may override this method simply to avoid back-and-forth
	 *           conversions between {@code String}s and {@code byte[]}s.
	 * 
	 * @param console the console producing the output
	 * @param channel identifies the "output stream", stdout or stderr
	 * @param text the output text
	 */
	default void consoleOutput(TargetObject console, Channel channel, String text) {
		consoleOutput(console, channel, text.getBytes(TargetConsole.CHARSET));
	}

	/**
	 * A "special" event has occurred
	 * 
	 * <p>
	 * When present, this callback must be invoked before any other callback which results from this
	 * event, except creation events. E.g., for PROCESS_EXITED, this must be called before the
	 * affected process is invalidated.
	 * 
	 * <p>
	 * Whenever possible, event thread must be given. This is often the thread given focus by the
	 * debugger immediately upon stopping for the event. Parameters are not (yet) strictly
	 * specified, but it should include the stopped target, if that target is not already given by
	 * the event thread. It may optionally contain other useful information, such as an exit code,
	 * but no client should depend on that information being given.
	 * 
	 * <p>
	 * The best way to communicate to users what has happened is via the description. Almost every
	 * other result of an event is communicated by other means in the model, e.g., state changes,
	 * object creation, invalidation. The description should contain as much information as possible
	 * to cue users as to why the other changes have occurred, and point them to relevant objects.
	 * For example, if trapped on a breakpoint, the description might contain the breakpoint's
	 * identifier. If the debugger prints a message for this event, that message is probably a
	 * sufficient description.
	 * 
	 * @param object the event scope
	 * @param eventThread if applicable, the thread causing the event
	 * @param type the type of event
	 * @param description a human-readable description of the event
	 * @param parameters extra parameters for the event. TODO: Specify these for each type, or break
	 *            this into other callbacks.
	 */
	default void event(TargetObject object, TargetThread eventThread, TargetEventType type,
			String description, List<Object> parameters) {
	}

	/**
	 * Memory was successfully read or written
	 * 
	 * <p>
	 * This implies memory caches should be updated. If the implementation employs a cache, then it
	 * need only report reads or writes which updated that cache. However, that cache must be
	 * invalidated whenever any other event occurs which could change memory, e.g., the target
	 * stepping or running. See {@link #invalidateCacheRequested(TargetObject)}. If the
	 * implementation does not employ a cache, then it must report <em>every</em> successful
	 * client-driven read or write. If the implementation can detect <em>debugger-driven</em> memory
	 * reads and writes, then it is recommended to call this method for those events. However, this
	 * method <em>must not</em> be called for <em>target-driven</em> memory changes. In other words,
	 * this method should only be called for reads or writes requested by the user.
	 * 
	 * @param memory this memory object
	 * @param address the starting address of the affected range
	 * @param data the new data for the affected range
	 */
	default void memoryUpdated(TargetObject memory, Address address, byte[] data) {
	}

	/**
	 * An attempt to read memory failed
	 * 
	 * <p>
	 * Like {@link #memoryUpdated(TargetMemory, Address, byte[])}, this should only be invoked for
	 * <em>user-driven</em> requests. Failure of the <em>target</em> to read its own memory would
	 * likely be reported via an exception, not this callback.
	 * 
	 * @param memory the memory object
	 * @param range the range for the read which generated the error
	 * @param e the error
	 */
	default void memoryReadError(TargetObject memory, AddressRange range,
			DebuggerMemoryAccessException e) {
	}

	/**
	 * Registers were successfully read or written
	 * 
	 * <p>
	 * This implies register caches should be updated. If the implementation employs a cache, then
	 * it need only report reads or writes which updated that cache. However, that cache must be
	 * invalidated whenever any other event occurs which could change register values, e.g., the
	 * target stepping or running. See {@link #invalidateCacheRequested(TargetObject)}. If the
	 * implementation doe not employ a cache, then it must report <em>every</em> successful
	 * client-driven read or write. If the implementation can detect <em>debugger-driven</em>
	 * register reads and writes, then it recommended to call this method for those events. However,
	 * this method <em>must not</em> be called for <em>target-driven</em> register changes, except
	 * perhaps when the target becomes suspended. Note that some models may additionally provide a
	 * {@code value} attribute on each register -- when the register bank is its own description
	 * container -- however, updating those attributes is not a substitute for this callback.
	 * 
	 * @param bank this register bank object
	 * @param updates a name-value map of updated registers
	 */
	default void registersUpdated(TargetObject bank, Map<String, byte[]> updates) {
	}
}
