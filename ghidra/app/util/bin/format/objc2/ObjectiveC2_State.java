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
package ghidra.app.util.bin.format.objc2;

import ghidra.app.util.bin.format.objectiveC.ObjectiveC1_State;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class ObjectiveC2_State extends ObjectiveC1_State {

	/**
	 * A map of the index where the class structure was defined to instantiated class object.
	 */
	public final Map<Long, ObjectiveC2_Class> classIndexMap = new HashMap<Long, ObjectiveC2_Class>();

	/**
	 * A map of instance variable addresses to mangled type strings.
	 */
	public final Map<Address, ObjectiveC2_InstanceVariable> variableMap = new HashMap<Address, ObjectiveC2_InstanceVariable>();

	public ObjectiveC2_State(Program program, TaskMonitor monitor, CategoryPath categoryPath) {
		super(program, monitor, categoryPath);
	}

	@Override
	public void dispose() {
		super.dispose();
		classIndexMap.clear();
		variableMap.clear();
	}

	@Override
	public List<String> getObjectiveCSectionNames() {
		return ObjectiveC2_Constants.getObjectiveC2SectionNames();
	}
}
