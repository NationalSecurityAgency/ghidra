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
package agent.dbgeng.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.dbgeng.model.iface1.DbgModelTargetEventScope;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetModuleContainer;

public interface DbgModelTargetModuleContainer
		extends /*DbgModelTargetObject,*/ DbgModelTargetEventScope, TargetModuleContainer {

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name);

	public DbgModelTargetModule getTargetModule(String name);

	public void libraryLoaded(String name);

	public void libraryUnloaded(String name);

}
