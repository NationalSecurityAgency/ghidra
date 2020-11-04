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
package ghidra.app.plugin.core.function.tags;

import java.util.Objects;

import ghidra.program.model.listing.FunctionTag;

/**
 * This class provides an implementation of the {@link FunctionTag} interface for
 * tags that are not yet ready to be inserted into the database. This was created
 * to allow tags to be imported from an external file and made available to the user
 * through the {@link FunctionTagProvider} UI without needing to formally
 * add them to the {@code FunctionTagAdapter} table.
 */
class InMemoryFunctionTag implements FunctionTag {

	private final String name;
	private final String comment;

	InMemoryFunctionTag(String name, String comment) {
		this.name = name;
		this.comment = comment == null ? "" : comment;
	}

	@Override
	public long getId() {
		return -1;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public String getComment() {
		return comment;
	}

	@Override
	public void setName(String name) {
		throw new UnsupportedOperationException("immutable tag");
	}

	@Override
	public void setComment(String comment) {
		throw new UnsupportedOperationException("immutable tag");
	}

	@Override
	public int compareTo(FunctionTag otherTag) {
		int rc = getName().compareToIgnoreCase(otherTag.getName());
		if (rc != 0) {
			return rc;
		}
		return getComment().compareToIgnoreCase(otherTag.getComment());
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((comment == null) ? 0 : comment.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (!(obj instanceof FunctionTag)) {
			return false;
		}

		FunctionTag other = (FunctionTag) obj;
		if (!Objects.equals(comment, other.getComment())) {
			return false;
		}

		if (!Objects.equals(name, other.getName())) {
			return false;
		}

		return true;
	}

	@Override
	public void delete() {
		// These items cannot be deleted, so do nothing
	}

	@Override
	public String toString() {
		return "In-memory tag: " + name;
	}
}
