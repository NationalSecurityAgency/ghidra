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

import java.util.List;

/**
 * A {@link AssemblyResolution} indicating the occurrence of a (usually semantic) error
 * 
 * <p>
 * The description should indicate where the error occurred. The error message should explain the
 * actual error. To help the user diagnose the nature of the error, errors in sub-constructors
 * should be placed as children of an error given by the parent constructor.
 */
public class DefaultAssemblyResolvedError extends AbstractAssemblyResolution
		implements AssemblyResolvedError {
	protected final String error;

	@Override
	protected int computeHash() {
		return error.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (this.getClass() != obj.getClass()) {
			return false;
		}
		DefaultAssemblyResolvedError that = (DefaultAssemblyResolvedError) obj;
		if (!this.error.equals(that.error)) {
			return false;
		}
		return true;
	}

	protected DefaultAssemblyResolvedError(AbstractAssemblyResolutionFactory<?, ?> factory,
			String description, List<? extends AssemblyResolution> children,
			AssemblyResolution right, String error) {
		super(factory, description, children, right);
		this.error = error;
	}

	@Override
	public boolean isError() {
		return true;
	}

	@Override
	public boolean isBackfill() {
		return false;
	}

	/**
	 * Get a description of the error
	 * 
	 * @return the description
	 */
	@Override
	public String getError() {
		return error;
	}

	@Override
	public String lineToString() {
		return error + " (" + description + ")";
	}

	@Override
	public AssemblyResolution shift(int amt) {
		return this;
	}

	@Override
	public AssemblyResolution withRight(AssemblyResolution right) {
		return factory.newErrorBuilder()
				.error(error)
				.description(description)
				.children(children)
				.right(right)
				.build();
	}

	@Override
	public AssemblyResolution parent(String description, int opCount) {
		return factory.newErrorBuilder()
				.error(error)
				.description(description)
				.children(getAllRight())
				.build();
	}
}
