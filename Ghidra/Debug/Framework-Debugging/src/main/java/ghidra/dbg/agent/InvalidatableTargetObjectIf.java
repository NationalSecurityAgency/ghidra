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
package ghidra.dbg.agent;

import java.util.*;

import ghidra.dbg.target.TargetObject;

/**
 * An interface for {@link TargetObject} implementations which would like notifications of
 * invalidation from parents whose implementations derive from {@link AbstractTargetObject}.
 * 
 * <p>
 * This is a mechanism used internally by model implementations to manage invalidation of subtrees
 * according to conventions. If every object implementation in the model is based on
 * {@link AbstractTargetObject} (or {@link DefaultTargetObject}), then this is all taken care of.
 * The implementor need only call {@link DefaultTargetObject#setAttributes(Map, String)} or similar,
 * and invalidation is taken care of. To invalidate the entire model, simply call
 * {@link #invalidateSubtree(String)} on the root.
 * 
 * <p>
 * Explicitly implementing this interface becomes necessary when there exists a mixture of objects
 * in the model, some derived from {@link AbstractTargetObject} and some not, including cases where
 * {@link AbstractTargetObject} is obscured by a proxy scheme. A parent based on
 * {@link AbstractTargetObject} will call {@link #invalidateSubtree(String)} on any of its children
 * being removed from the model, including when the parent is invalidated. The implementation should
 * release its resources and also invalidate its children accordingly. For the case of a proxy whose
 * delegate derives from {@link AbstractTargetObject}, the proxy must include this interface, and
 * the call need only be forwarded to the delegate.
 */
public interface InvalidatableTargetObjectIf extends TargetObject {

	/**
	 * Invalidate this subtree
	 * 
	 * <p>
	 * In most cases, this need only be invoked on the root to destroy the entire model, or if the
	 * implementation is managing the collections of children. Otherwise,
	 * {@link DefaultTargetObject#changeAttributes(List, Map, String)},
	 * {@link DefaultTargetObject#changeElements(Collection, Collection, String)},
	 * {@link DefaultTargetObject#setAttributes(Map, String)}, and
	 * {@link DefaultTargetObject#setElements(Collection, String)} will automatically invoke this
	 * method when they detect object removal.
	 * 
	 * @param branch the root of the sub-tree that is being removed
	 * @param reason a human-consumable explanation for the removal
	 */
	void invalidateSubtree(TargetObject branch, String reason);

	/**
	 * Invalidate this subtree, without locking
	 * 
	 * <p>
	 * This really only exists to avoid reentering a lock. This should be called when a thread has
	 * already acquired the relevant lock(s).
	 * 
	 * @param branch
	 * @param reason
	 */
	void doInvalidateSubtree(TargetObject branch, String reason);
}
