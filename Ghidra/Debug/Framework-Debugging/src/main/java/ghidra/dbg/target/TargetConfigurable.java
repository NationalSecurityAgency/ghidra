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

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.TargetMethod.ParameterDescription;

/**
 * A target with writable configuration options
 * 
 * <p>
 * In general, the options are also stored as attributes, so that the current values are retrievable
 * by the client. Note that not every attribute denotes a writable option. The list of configurable
 * options, along with a description of each, is retrieved using {@link #getConfigurableOptions()}.
 * 
 * <p>
 * Options should be close to their scope of applicability. For example, if an object affects the
 * whole model, it should be an option of the root, or perhaps an option of a top-level "Options"
 * object. If an option affects an object's elements, that option should be on the containing
 * object. If an option affects a singular object, that option should probably be on that object
 * itself.
 * 
 * <p>
 * Furthermore, writing an option should not be the means of triggering an action. Though certainly,
 * the model may react to their modification. Actions, in general, should instead be exposed as
 * {@link TargetMethod}s.
 */
@DebuggerTargetObjectIface("Configurable")
public interface TargetConfigurable extends TargetObject {

	String BASE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "base";

	/**
	 * Write a single option to this object
	 * 
	 * <p>
	 * TODO: This should probably be replaced with a {@code configure(Map<String,Object> options)}
	 * method. That should also make it easy to validate the arguments using the same mechanisms as
	 * for {@link TargetMethod#invoke(Map)}.
	 * 
	 * @param key the name of the option, typically corresponding to the same-named attribute
	 * @param value the value to assign the option, typically conforming to the attribute schema
	 * @return a future which completes when the change is processed.
	 * @throws {@link DebuggerIllegalArgumentException} if the key is not writable, or if the value
	 *             is not valid.
	 */
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value);

	/**
	 * Get the map of writable configuration options
	 * 
	 * <p>
	 * TODO: Implement this properly in all subclasses to advertise their parameters. Then remove
	 * this default implementation.
	 * 
	 * @return a map of names to option descriptions
	 */
	public default Map<String, ParameterDescription<?>> getConfigurableOptions() {
		return new HashMap<>();
	}
}
