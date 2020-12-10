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

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.model.iface2.DbgModelTargetAvailable;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebuggerObjectModel;
import ghidra.dbg.attributes.TargetObjectRef;
import ghidra.dbg.attributes.TypedTargetObjectRef;
import ghidra.dbg.target.*;
import ghidra.util.Msg;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetAttacher<T extends TargetAttacher<T>>
		extends DbgModelTargetObject, TargetAttacher<T> {

	@Override
	public default CompletableFuture<Void> attach(
			TypedTargetObjectRef<? extends TargetAttachable<?>> ref) {
		getModel().assertMine(TargetObjectRef.class, ref);
		List<String> tPath = ref.getPath();
		AtomicReference<DbgProcess> process = new AtomicReference<>();
		AtomicReference<DbgModelTargetAvailable> attachable = new AtomicReference<>();
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			getModel().fetchModelObject(tPath).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((obj, seq) -> {
			attachable.set((DbgModelTargetAvailable) DebuggerObjectModel.requireIface(
				TargetAttachable.class, obj, tPath));
			getManager().addProcess().handle(seq::next);
		}, process).then(seq -> {
			process.get().attach((int) attachable.get().getPid()).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "attach failed");
			return null;
		});
	}

	@Override
	public default CompletableFuture<Void> attach(long pid) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DbgProcess process = new DbgProcessImpl(getManager());
			process.attach(pid).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "attach failed");
			return null;
		});
	}

}
