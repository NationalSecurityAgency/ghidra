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
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;

@TargetObjectSchemaInfo(
	name = "Selectable",
	attributes = {
		@TargetAttributeType(type = Void.class) })
public interface DbgModelSelectableObject extends DbgModelTargetObject {

	public default CompletableFuture<Void> setActive() {
		if (this instanceof DbgModelTargetSession) {
			DbgManagerImpl manager = getManager();
			DbgProcess process = manager.getCurrentProcess();
			return process.setActive();
		}
		if (this instanceof DbgModelTargetProcess) {
			DbgModelTargetProcess tp = (DbgModelTargetProcess) this;
			DbgProcess process = tp.getProcess();
			return process.setActive();
		}
		if (this instanceof DbgModelTargetThread) {
			DbgModelTargetThread tt = (DbgModelTargetThread) this;
			DbgThread thread = tt.getThread();
			return thread.setActive();
		}
		if (this instanceof DbgModelTargetStackFrame) {
			DbgModelTargetStackFrame tf = (DbgModelTargetStackFrame) this;
			TargetObject ref = tf.getThread();
			if (ref instanceof DbgModelTargetThread) {
				DbgModelTargetThread tt = (DbgModelTargetThread) ref;
				DbgThread thread = tt.getThread();
				return thread.setActive();
			}
		}
		return CompletableFuture.completedFuture(null);
	}

}
