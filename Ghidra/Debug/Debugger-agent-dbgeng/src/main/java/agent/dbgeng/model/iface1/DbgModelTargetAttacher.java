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

import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.model.iface2.DbgModelTargetAvailable;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetAttacher;
import ghidra.util.Msg;

/**
 * An interface which indicates this object is capable of launching targets.
 * 
 * <p>
 * The targets this launcher creates ought to appear in its successors.
 * 
 * @param <T> type for this
 */
public interface DbgModelTargetAttacher extends DbgModelTargetObject, TargetAttacher {

	@Override
	public default CompletableFuture<Void> attach(TargetAttachable attachable) {
		DbgModelTargetAvailable available =
			getModel().assertMine(DbgModelTargetAvailable.class, attachable);
		// TODO: This and the below new DbgProcessImpl seem to do the same thing
		// Both should be expressed the same way
		return getModel().gateFuture(getManager().addProcess().thenCompose(process -> {
			return process.attach(available.getPid());
		}).exceptionally(exc -> {
			Msg.error(this, "attach failed");
			return null;
		})).thenApply(__ -> null);
	}

	@Override
	public default CompletableFuture<Void> attach(long pid) {
		DbgProcess process = new DbgProcessImpl(getManager());
		return getModel().gateFuture(process.attach(pid).exceptionally(exc -> {
			Msg.error(this, "attach failed");
			return null;
		})).thenApply(__ -> null);
	}
}
