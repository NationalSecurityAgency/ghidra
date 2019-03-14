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
package ghidra.app.plugin.core.stackeditor;

import ghidra.program.model.data.*;

public interface BiDirectionStructure extends Structure {

	/**
	 * Get the length of this DataType in the negative direction.
	 * @return the length of this DataType in the negative direction.
	 */
	public abstract int getNegativeLength();

	/**
	 * Get the length of this DataType in the positive direction.
	 * @return the length of this DataType in the positive direction.
	 */
	public abstract int getPositiveLength();

	/**
	 * Get the component offset which represents the division point
	 * between the positive and negative halves of the structure.
	 * @return
	 */
	public abstract int getSplitOffset();

	public DataTypeComponent addNegative(DataType dataType, int length, String name, String comment);

	public DataTypeComponent addPositive(DataType dataType, int length, String name, String comment);
}
