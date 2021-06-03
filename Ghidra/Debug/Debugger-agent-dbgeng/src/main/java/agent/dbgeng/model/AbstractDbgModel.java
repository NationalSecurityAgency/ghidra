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
package agent.dbgeng.model;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.model.iface2.DbgModelTargetSession;
import ghidra.dbg.agent.AbstractDebuggerObjectModel;
import ghidra.dbg.target.TargetObject;
import ghidra.program.model.address.AddressFactory;

public abstract class AbstractDbgModel extends AbstractDebuggerObjectModel {

	public abstract DbgManager getManager();

	public abstract CompletableFuture<Void> startDbgEng(String[] args);

	public abstract boolean isRunning();

	public abstract void terminate() throws IOException;

	public abstract AddressFactory getAddressFactory();

	public abstract DbgModelTargetSession getSession();

	public abstract void addModelObject(Object object, TargetObject targetObject);

	public abstract TargetObject getModelObject(Object object);

}
