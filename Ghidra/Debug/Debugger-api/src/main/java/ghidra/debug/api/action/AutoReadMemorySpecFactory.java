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
package ghidra.debug.api.action;

import java.util.*;

import ghidra.framework.plugintool.PluginTool;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A discoverable factory of auto-read memory specifications
 */
public interface AutoReadMemorySpecFactory extends ExtensionPoint {

	/**
	 * Get the specification for the given configuration name
	 * 
	 * @param name the name
	 * @return the spec, or null
	 */
	static AutoReadMemorySpec fromConfigName(String name) {
		for (AutoReadMemorySpecFactory factory : ClassSearcher
				.getInstances(AutoReadMemorySpecFactory.class)) {
			AutoReadMemorySpec spec = factory.parseSpec(name);
			if (spec != null) {
				return spec;
			}
		}
		return null;
	}

	/**
	 * Get a copy of all the known and visible specifications
	 * 
	 * @param tool the plugin tool or context
	 * @return the specifications by configuration name
	 */
	static Map<String, AutoReadMemorySpec> allSuggested(PluginTool tool) {
		Map<String, AutoReadMemorySpec> all = new TreeMap<>();
		for (AutoReadMemorySpecFactory factory : ClassSearcher
				.getInstances(AutoReadMemorySpecFactory.class)) {
			for (AutoReadMemorySpec spec : factory.getSuggested(tool)) {
				if (spec.getMenuName() != null) {
					all.put(spec.getConfigName(), spec);
				}
			}
		}
		return all;
	}

	/**
	 * Get all the specifications currently suggested by this factory
	 * 
	 * @param tool the plugin tool or context
	 * @return the list of suggested specifications
	 */
	List<AutoReadMemorySpec> getSuggested(PluginTool tool);

	/**
	 * Attempt to parse the given configuration name as a specification
	 * 
	 * @param name the configuration name, usually including a prefix unique to each factory
	 * @return the specification, or null if this factory cannot parse it
	 */
	AutoReadMemorySpec parseSpec(String name);
}
