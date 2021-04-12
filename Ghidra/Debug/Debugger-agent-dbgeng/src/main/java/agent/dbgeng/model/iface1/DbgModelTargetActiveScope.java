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
package agent.dbgeng.model.iface1;

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.async.AsyncUtils;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetActiveScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetActiveScope extends DbgModelTargetObject, TargetActiveScope {

	// NB: requesActivation request change in active object - propagates down to manager
	//  (but, of course, may then cause change in state)
	@Override
	public default CompletableFuture<Void> requestActivation(TargetObject obj) {
		return getModel().gateFuture(getManager().requestActivation(this, obj));
	}

	public default CompletableFuture<Void> doRequestActivation(TargetObject obj) {
		if (getManager().isWaiting()) {
			return AsyncUtils.NIL;
		}
		getModel().assertMine(TargetObject.class, obj);
		if (!PathUtils.isAncestor(this.getPath(), obj.getPath())) {
			throw new DebuggerIllegalArgumentException("Can only focus a successor of the scope");
		}
		TargetObject cur = obj;
		while (cur != null) {
			if (cur instanceof DbgModelSelectableObject) {
				DbgModelSelectableObject sel = (DbgModelSelectableObject) cur;
				//System.err.println("requestActivation " + obj);
				return sel.setActive();
			}
			if (cur instanceof DbgModelTargetObject) {
				DbgModelTargetObject def = (DbgModelTargetObject) cur;
				cur = def.getParent();
				continue;
			}
			throw new AssertionError();
		}
		return AsyncUtils.NIL;
	}

}
