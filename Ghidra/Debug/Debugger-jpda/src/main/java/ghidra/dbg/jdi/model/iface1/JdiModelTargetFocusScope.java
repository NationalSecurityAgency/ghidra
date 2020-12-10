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
package ghidra.dbg.jdi.model.iface1;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.error.DebuggerIllegalArgumentException;
import ghidra.dbg.jdi.model.iface2.JdiModelTargetObject;
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
public interface JdiModelTargetFocusScope<T extends TargetFocusScope<T>>
		extends JdiModelTargetObject, TargetFocusScope<T> {

	@Override
	public JdiModelSelectableObject getFocus();

	// NB: setFocus changes attributes - propagates up to client
	public boolean setFocus(JdiModelSelectableObject sel);

	// NB: requestFocus request change in active object - propagates down to manager
	//  (but, of course, may then cause change in state)
	@Override
	public default CompletableFuture<Void> requestFocus(TargetObjectRef ref) {
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
				if (cur instanceof JdiModelSelectableObject) {
					JdiModelSelectableObject sel = (JdiModelSelectableObject) cur;
					sel.select().handle(seq::exit);
					AtomicReference<JdiModelTargetFocusScope<?>> scope = new AtomicReference<>();
					AsyncUtils.sequence(TypeSpec.VOID).then(seqx -> {
						DebugModelConventions.findSuitable(JdiModelTargetFocusScope.class, sel)
								.handle(seqx::next);
					}, scope).then(seqx -> {
						scope.get().setFocus(sel);
					}).finish();
					break;
				}
				if (cur instanceof JdiModelTargetObject) {
					JdiModelTargetObject def = (JdiModelTargetObject) cur;
					cur = def.getImplParent();
					continue;
				}
				throw new AssertionError();
			}
			seq.exit();
		}).finish();
	}

}
