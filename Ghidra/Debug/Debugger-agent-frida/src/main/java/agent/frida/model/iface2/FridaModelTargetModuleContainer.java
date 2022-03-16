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
package agent.frida.model.iface2;

import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaModuleInfo;
import agent.frida.manager.*;
import agent.frida.model.iface1.FridaModelTargetEventScope;
import ghidra.dbg.target.TargetModule;
import ghidra.dbg.target.TargetModuleContainer;

public interface FridaModelTargetModuleContainer
		extends FridaModelTargetEventScope, //
		TargetModuleContainer, //
		FridaEventsListenerAdapter {

	@Override
	public CompletableFuture<? extends TargetModule> addSyntheticModule(String name);

	public FridaModelTargetModule getTargetModule(FridaModule module);

	public void moduleLoaded(FridaProcess proc, FridaModuleInfo info, int index, FridaCause cause);

	public void moduleReplaced(FridaProcess proc, FridaModuleInfo info, int index, FridaCause cause);

	public void moduleUnloaded(FridaProcess proc, FridaModuleInfo info, int index, FridaCause cause);

}
