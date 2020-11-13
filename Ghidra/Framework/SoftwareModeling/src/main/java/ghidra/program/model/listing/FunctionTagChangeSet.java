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
package ghidra.program.model.listing;

import ghidra.framework.model.ChangeSet;

/**
 * Defines a Function Tag Change set.  This is meant to track changes that
 * are made to {@link FunctionTag} objects in a program.
 */
public interface FunctionTagChangeSet extends ChangeSet {
	
	/**
	 * Indicates that a tag has been changed (edited/deleted).
	 * 
	 * @param id the id of the tag (from {@link ghidra.program.database.function.FunctionTagAdapter FunctionTagAdapter})
	 */
	void tagChanged(long id);

	/**
	 * Indicates that a tag has been created.
	 * 
	 * @param id id the id of the tag (from {@link ghidra.program.database.function.FunctionTagAdapter FunctionTagAdapter})
	 */
	void tagCreated(long id);

	/**
	 * Returns a list of all tag ids that have been changed (edited/deleted).
	 * 
	 * @return the list of tag ids (from {@link ghidra.program.database.function.FunctionTagAdapter FunctionTagAdapter})
	 */
	long[] getTagChanges();
	
	/**
	 * Returns a list of all tag ids that have been created.
	 * 
	 * @return the list of tag ids (from {@link ghidra.program.database.function.FunctionTagAdapter FunctionTagAdapter})
	 */
	long[] getTagCreations();

}
