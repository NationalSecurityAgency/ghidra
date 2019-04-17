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
package ghidra.sleigh.grammar;

import generic.stl.Pair;
import ghidra.pcodeCPort.slgh_compile.PreprocessorDefinitions;

import java.util.HashMap;

public class HashMapPreprocessorDefinitionsAdapter implements PreprocessorDefinitions {

	private final HashMap<String, String> map;

	public HashMapPreprocessorDefinitionsAdapter() {
		this.map = new HashMap<String, String>();
	}

	@Override
	public Pair<Boolean, String> lookup(String key) {
		if (map.containsKey(key)) {
			return new Pair<Boolean, String>(true, map.get(key));
		}
		return new Pair<Boolean, String>(false, null);
	}

	@Override
	public void set(String key, String value) {
		map.put(key, value);
	}

	@Override
	public void undefine(String key) {
		map.remove(key);
	}
}
