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
package ghidra.app.plugin.assembler;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;

import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedError;

/**
 * Thrown when all resolutions of an assembly instruction result in semantic errors.
 * 
 * For SLEIGH, semantic errors amount to incompatible contexts
 */
public class AssemblySemanticException extends AssemblyException {
	protected Set<AssemblyResolvedError> errors;

	public AssemblySemanticException(String message) {
		super(message);
	}

	/**
	 * Construct a semantic exception with the associated semantic errors
	 * @param errors the associated semantic errors
	 */
	public AssemblySemanticException(Set<AssemblyResolvedError> errors) {
		super(StringUtils.join(errors, "\n"));
		this.errors = errors;
	}

	/**
	 * Get the collection of associated semantic errors
	 * @return the collection
	 */
	public Collection<AssemblyResolvedError> getErrors() {
		return Collections.unmodifiableCollection(errors);
	}
}
