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
package ghidra.app.util.bin.format.golang.structmapping;

import java.io.IOException;
import java.util.List;

import ghidra.util.exception.CancelledException;

/**
 * Optional interface that structure mapped classes can implement that allows them to control how
 * their class is marked up.
 * <p>
 * TODO: possibly refactor these methods to take a StructureContext parameter, which will
 * allow removing the getStructureContext method.
 * 
 * @param <T> structure mapped class
 */
public interface StructureMarkup<T> {

	StructureContext<T> getStructureContext();

	/**
	 * Returns the name of the instance, typically retrieved from data found inside the instance.
	 * 
	 * @return string name, or null if this instance does not have a name
	 * @throws IOException if error getting name
	 */
	default String getStructureName() throws IOException {
		return null;
	}

	/**
	 * Returns a string that can be used to place a label on the instance.
	 * <p>
	 * This default implementation will query the {@link #getStructureName()} method, and if
	 * it provides a value, will produce a string that looks like "name___mappingstructname", where
	 * "mappingstructname" will be the {@code structureName} value in the {@code @StructureMapping}
	 * annotation.
	 *  
	 * @return string to be used as a label, or null if there is not a valid label for the instance
	 * @throws IOException if error getting label
	 */
	default String getStructureLabel() throws IOException {
		String name = getStructureName();
		return name != null
				? "%s___%s".formatted(name,
					getStructureContext().getMappingInfo().getStructureName())
				: null;
	}

	/**
	 * Returns the namespace that any labels should be placed in.
	 * 
	 * @return name of namespace to place the label for this structure mapped type, or null
	 * @throws IOException if error generating namespace name
	 */
	default String getStructureNamespace() throws IOException {
		return null;
	}

	/**
	 * Called to allow the implementor to perform custom markup of itself.
	 * 
	 * @param session state and methods to assist marking up the program
	 * @throws IOException if error during markup
	 * @throws CancelledException if cancelled
	 */
	default void additionalMarkup(MarkupSession session) throws IOException, CancelledException {
		// empty
	}

	/**
	 * Returns a list of items that should be recursively marked up.
	 * 
	 * @return list of structure mapped object instances that should be marked up
	 * @throws IOException if error getting instances
	 */
	default List<?> getExternalInstancesToMarkup() throws IOException {
		return List.of();
	}
}
