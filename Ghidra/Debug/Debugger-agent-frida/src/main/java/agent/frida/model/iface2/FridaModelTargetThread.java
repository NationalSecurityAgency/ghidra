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

import agent.frida.manager.*;
import agent.frida.model.iface1.FridaModelSelectableObject;
import agent.frida.model.iface1.FridaModelTargetExecutionStateful;
import agent.frida.model.impl.FridaModelTargetStackImpl;
import ghidra.dbg.target.*;

public interface FridaModelTargetThread extends //
		TargetThread, //
		//FridaModelTargetAccessConditioned, //
		FridaModelTargetExecutionStateful, //
		//FridaModelTargetSteppable, //
		FridaStateListener, //
		FridaEventsListenerAdapter, //
		FridaModelSelectableObject {

	public default FridaThread getThread() {
		return (FridaThread) getModelObject();
	}

	public default void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		TargetRegisterContainer container =
			(TargetRegisterContainer) getCachedAttribute("Registers");
		TargetRegisterBank bank = (TargetRegisterBank) container.getCachedAttribute("User");
		if (state.equals(FridaState.FRIDA_THREAD_STOPPED)) {
			bank.readRegistersNamed(getCachedElements().keySet());
		}
	}

	@Override
	public default CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	public FridaModelTargetStackImpl getStack();

	public String getExecutingProcessorType();

}
