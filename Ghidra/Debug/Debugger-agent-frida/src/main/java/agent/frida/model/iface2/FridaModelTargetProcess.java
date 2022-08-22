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

import agent.frida.manager.FridaEventsListenerAdapter;
import agent.frida.manager.FridaProcess;
import agent.frida.model.iface1.*;
import ghidra.dbg.target.TargetAggregate;
import ghidra.dbg.target.TargetProcess;

public interface FridaModelTargetProcess extends //
		TargetAggregate, //
		TargetProcess, //
		FridaModelTargetExecutionStateful, //
		//FridaModelTargetAccessConditioned, //
		FridaModelTargetAttacher, //
		FridaModelTargetAttachable, //
		FridaModelTargetLauncher, //
		FridaModelTargetDeletable, //
		FridaModelTargetDetachable, //
		FridaModelTargetKillable, //
		FridaModelTargetResumable, //
		//FridaModelTargetSteppable, //
		//FridaModelTargetInterruptible, // 
		FridaEventsListenerAdapter, //
		FridaModelSelectableObject {

	public void processStarted(FridaProcess proc);

	public FridaModelTargetThreadContainer getThreads();

	public FridaModelTargetMemoryContainer getMemory();
	
	public FridaProcess getProcess();

	@Override
	public CompletableFuture<Void> setActive();


}
