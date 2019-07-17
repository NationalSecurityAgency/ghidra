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
package ghidra.app.plugin.core.byteviewer;

import java.io.Serializable;

/**
 * Class used only during serialization to keep the model name and the
 * group size of the model.
 */
class DataModelInfo implements Serializable {

	private String[] names;
	private int[] groupSizes;

	/**
	 * Constructor
	 * @param id name of the model
	 * @param groupSize group size for the model
	 */
	DataModelInfo(int size) {
		names = new String[size];
		groupSizes = new int[size];
	}

	void set(int index, String name, int groupSize) {
		names[index] = name;
		groupSizes[index] = groupSize;
	}

	/**
	 * Get the name of the model.
	 *
	 * @return String
	 */
	String[] getNames() {
		return names;
	}
}
