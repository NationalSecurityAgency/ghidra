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
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.PathUtils;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetFocusScope<T extends TargetFocusScope<T>>
		extends DbgModelTargetObject, TargetFocusScope<T> {

	@Override
	public DbgModelSelectableObject getFocus();

	// NB: setFocus changes attributes - propagates up to client
	public boolean setFocus(DbgModelSelectableObject sel);

	// NB: requestFocus request change in active object - propagates down to manager
	//  (but, of course, may then cause change in state)
	@Override
	public default CompletableFuture<Void> requestFocus(TargetObjectRef ref) {
		if (getManager().isWaiting()) {
			return CompletableFuture.completedFuture(null);
		}
		getModel().assertMine(TargetObjectRef.class, ref);
		if (ref.equals(getFocus())) {
			return CompletableFuture.completedFuture(null);
		}
		if (!PathUtils.isAncestor(this.getPath(), ref.getPath())) {
			throw new DebuggerIllegalArgumentException("Can only focus a successor of the scope");
		}
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			ref.fetch().handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
			TargetObject cur = obj;
			while (cur != null) {
				if (cur instanceof DbgModelSelectableObject) {
					DbgModelSelectableObject sel = (DbgModelSelectableObject) cur;
					sel.select().handle(seq::exit);
					AtomicReference<DbgModelTargetFocusScope<?>> scope = new AtomicReference<>();
					AsyncUtils.sequence(TypeSpec.VOID).then(seqx -> {
						DebugModelConventions.findSuitable(DbgModelTargetFocusScope.class, sel)
								.handle(seqx::next);
					}, scope).then(seqx -> {
						scope.get().setFocus(sel);
					}).finish();
					break;
				}
				if (cur instanceof DbgModelTargetObject) {
					DbgModelTargetObject def = (DbgModelTargetObject) cur;
					cur = def.getImplParent();
					continue;
				}
				throw new AssertionError();
			}
			seq.exit();
		}).finish();
	}

}
