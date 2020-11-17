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
package help;

import java.util.Map;

import help.validator.model.TOCItemDefinition;
import help.validator.model.TOCItemExternal;

/**
 * An interface that allows us to perform dependency injection in the testing environment
 */
public interface TOCItemProvider {

	/**
	 * Returns all external TOC items referenced by this provider
	 * @return the items
	 */
	public Map<String, TOCItemExternal> getExternalTocItemsById();

	/**
	 * Returns all TOC items defined by this provider
	 * @return the items
	 */
	public Map<String, TOCItemDefinition> getTocDefinitionsByID();
}
