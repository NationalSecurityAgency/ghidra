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
package ghidra.dbg.target;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;

/**
 * A target that can be interrupted
 */
@DebuggerTargetObjectIface("Interruptible")
public interface TargetInterruptible extends TargetObject {

	/**
	 * Interrupt the target object
	 * 
	 * <p>
	 * Typically, this breaks, i.e., stops, all target objects in scope of the receiver. Note the
	 * command completes when the interrupt has been sent, whether or not it actually stopped
	 * anything. Users wishing to confirm execution has stopped should wait for the target object to
	 * enter the {@link TargetExecutionState#STOPPED} state. Depending on the temperament of the
	 * debugger and the target, it may be necessary to send multiple interrupts.
	 * 
	 * @return a future which completes when the interrupt has been sent
	 */
	public CompletableFuture<Void> interrupt();
}
