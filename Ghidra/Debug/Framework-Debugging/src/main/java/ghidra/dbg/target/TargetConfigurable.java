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

/**
 * A target with writable configuration options
 * 
 * <p>
 * In general, the options are stored as attributes, so that the current values are retrievable by
 * the client, and so that the names and types of options are known. Note that not every attribute
 * denotes a writable option. Enumeration of available options is not yet specified, but for the
 * moment, we assume a subset of the attributes.
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
	 * @param key the name of the option, typically corresponding to the same-named attribute
	 * @param value the value to assign the option, typically conforming to the attribute schema
	 * @return a future which completes when the change is processed.
	 * @throws {@link DebuggerIllegalArgumentException} if the key is not writable, or if the value
	 *             is not valid.
	 */
	public CompletableFuture<Void> writeConfigurationOption(String key, Object value);
}
