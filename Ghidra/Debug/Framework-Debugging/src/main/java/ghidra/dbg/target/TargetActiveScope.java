/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

/**
 * An object made active
 * 
 * <p>
 * "Active" here describes which object in a given class the target should operate on
 * 
 * @deprecated Will be removed in 11.3. Portions may be refactored into trace object database.
 */
@Deprecated(forRemoval = true, since = "11.2")
@DebuggerTargetObjectIface("ActiveScope")
public interface TargetActiveScope extends TargetObject {

	/**
	 * Set the given object as the target's active object for the given type
	 * 
	 * @param obj the object to setActive
	 * @return a future which completes upon successfully changing focus.
	 */
	CompletableFuture<Void> requestActivation(TargetObject obj);

}
