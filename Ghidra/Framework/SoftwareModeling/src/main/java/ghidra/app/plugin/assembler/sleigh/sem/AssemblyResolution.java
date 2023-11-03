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
package ghidra.app.plugin.assembler.sleigh.sem;

import java.util.Collection;
import java.util.List;

public interface AssemblyResolution extends Comparable<AssemblyResolution> {

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Describe this record including indented children, grandchildren, etc., each on its own line.
	 */
	@Override
	String toString();

	String getDescription();

	List<AssemblyResolution> getChildren();

	/**
	 * Check if this record has children
	 * 
	 * <p>
	 * If a subclass has another, possibly additional, notion of children that it would like to
	 * include in {@link #toString()}, it must override this method to return true when such
	 * children are present.
	 * 
	 * @see #childrenToString(String)
	 * @return true if this record has children
	 */
	boolean hasChildren();

	AssemblyResolution getRight();

	/**
	 * Display the resolution result in one line (omitting child details)
	 * 
	 * @return the display description
	 */
	String lineToString();

	/**
	 * Check if this record describes a backfill
	 * 
	 * @return true if the record is a backfill
	 */
	boolean isBackfill();

	/**
	 * Check if this record describes an error
	 * 
	 * @return true if the record is an error
	 */
	boolean isError();

	/**
	 * Shift the resolution's instruction pattern to the right, if applicable
	 * 
	 * <p>
	 * This also shifts any backfill and forbidden pattern records.
	 * 
	 * @param amt the number of bytes to shift.
	 * @return the result
	 */
	AssemblyResolution shift(int amt);

	/**
	 * Get this same resolution, pushing its right siblings down to its children
	 */
	AssemblyResolution parent(String description, int opCount);

	void collectAllRight(Collection<AssemblyResolution> into);

	/**
	 * Used only by parents: get a multi-line description of this record, indented
	 * 
	 * @param indent the current indentation
	 * @return the indented description
	 */
	String toString(String indent);
}
