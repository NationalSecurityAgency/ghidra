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
package sarif.export.trees;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.data.ISF.IsfObject;
import ghidra.program.model.listing.Group;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.listing.ProgramModule;

public class ExtModule implements IsfObject {

	String name;
	String value;

	List<ExtModule> modules = new ArrayList<>();
	List<ExtFragment> fragments = new ArrayList<>();

	public ExtModule(String name, ProgramModule m, List<Object> visited) {
		this.name = name;
		if (!visited.contains(m)) {
			visited.add(m);
			Group[] children = m.getChildren();
			for (Group child : children) {
				if (child instanceof ProgramModule cm) {
					ExtModule module = new ExtModule(child.getName(), cm, visited);
					modules.add(module);
				} else if (child instanceof ProgramFragment cf) {
					ExtFragment fragment = new ExtFragment(cf, visited);
					fragments.add(fragment);
				}
			}
		}
	}

}
