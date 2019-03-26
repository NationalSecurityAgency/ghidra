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
package ghidra.program.model.listing;

import ghidra.framework.model.ChangeSet;

/**
 * Interface for a Program Tree Change set.  Objects that implements this interface track
 * various change information on a program tree manager.
 */
public interface ProgramTreeChangeSet extends ChangeSet {

	//
	// Program Tree
	//
	
	/**
	 * adds the program tree id to the list of trees that have changed.
	 */
	void programTreeChanged(long id);

	/**
	 * adds the program tree id to the list of trees that have been added.
	 */
	void programTreeAdded(long id);
	
	/**
	 * returns the list of program tree IDs that have changed.
	 */
	long[] getProgramTreeChanges();
	
	/**
	 * returns the list of program tree IDs that have been added.
	 */
	long[] getProgramTreeAdditions();

}
