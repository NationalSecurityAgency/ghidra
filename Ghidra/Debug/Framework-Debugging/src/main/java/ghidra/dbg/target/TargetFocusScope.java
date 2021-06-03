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
package ghidra.dbg.target;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * An object having a designated "focus"
 * 
 * <p>
 * Focus is usually communicated via various UI hints, but also semantically implies that actions
 * taken within this scope apply to the focused object. The least confusing option is to implement
 * this at the root, but that need not always be the case.
 */
@DebuggerTargetObjectIface("FocusScope")
public interface TargetFocusScope extends TargetObject {

	String FOCUS_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "focus";

	/**
	 * Focus on the given object
	 * 
	 * <p>
	 * {@code obj} must be successor of this scope. The debugger may reject or ignore the request
	 * for any reason. If the debugger cannot focus the given object, it should attempt to do so for
	 * each ancestor until it succeeds or reaches this focus scope.
	 * 
	 * @param obj the object to receive focus
	 * @return a future which completes upon successfully changing focus.
	 */
	CompletableFuture<Void> requestFocus(TargetObject obj);

	/**
	 * Get the focused object in this scope
	 * 
	 * <p>
	 * Note that client UIs should be careful about event loops and user intuition when listening
	 * for changes of this attribute. The client should avoid calling
	 * {@link #requestFocus(TargetObject)} in response. Perhaps the simplest way is to only request
	 * focus when the selected object has actually changed. The debugger may "adjust" the focus. For
	 * example, when focusing a thread, the debugger may instead focus a particular frame in that
	 * thread (a successor). Or, when focusing a memory region, the debugger may only focus the
	 * owning process (an ancestor). The suggested strategy (a work in progress) is the "same level,
	 * same type" rule. It may be appropriate to highlight the actual focused object to cue the user
	 * in, but the user's selection should remain at the same level. If an ancestor or successor
	 * receives focus, leave the user's selection as is. If a sibling element or one of its
	 * successors receives focus, select that sibling. A similar rule applies to "cousin" elements,
	 * so long as they have the same type. In most other cases, it's appropriate to select the
	 * focused element. TODO: Implement this rule in {@link DebugModelConventions}
	 * 
	 * @return a reference to the focused object or {@code null} if no object is focused.
	 */
	@TargetAttributeType(name = FOCUS_ATTRIBUTE_NAME, required = true, hidden = true)
	default TargetObject getFocus() {
		return getTypedAttributeNowByName(FOCUS_ATTRIBUTE_NAME, TargetObject.class, null);
	}
}
