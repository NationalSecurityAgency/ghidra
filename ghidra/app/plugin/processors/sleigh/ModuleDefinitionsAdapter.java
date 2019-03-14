/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.plugin.processors.sleigh;

import generic.stl.Pair;
import ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions;
import ghidra.sleigh.grammar.HashMapPreprocessorDefinitionsAdapter;

import java.util.HashMap;

public class ModuleDefinitionsAdapter implements PreprocessorDefinitions {
	private HashMapPreprocessorDefinitionsAdapter delegate;
	private HashMap<String, String> moduleMap;

	public ModuleDefinitionsAdapter() {
		this.delegate = new HashMapPreprocessorDefinitionsAdapter();
	}

	@Override
	public Pair<Boolean, String> lookup(String key) {
		Pair<Boolean, String> pair = delegate.lookup(key);
		if (pair.first) {
			return pair;
		}

		if (moduleMap == null) {
			moduleMap = new HashMap<String, String>(ModuleDefinitionsMap.getModuleMap());
		}

		String path = moduleMap.get(key);
		if (path == null) {
			return new Pair<Boolean, String>(false, null);
		}
		return new Pair<Boolean, String>(true, path);
	}

	@Override
	public void undefine(String key) {
		delegate.undefine(key);
	}

	@Override
	public void set(String key, String value) {
		delegate.set(key, value);
	}
}
