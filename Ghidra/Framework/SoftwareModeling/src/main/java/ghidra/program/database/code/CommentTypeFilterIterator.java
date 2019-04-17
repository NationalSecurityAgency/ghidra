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
package ghidra.program.database.code;

import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;

import java.util.Iterator;

/**
 * Filters the given codeUnit iterator to only return codeUnits that have a comment of the given type
 */
public class CommentTypeFilterIterator implements CodeUnitIterator {
	private CodeUnitIterator it;
	private int commentType;
	private CodeUnit nextCu;

	/**
	 * Constructs a new CommentTypeFilterIterator
	 * @param it a codeunit iterator whose items are tested for the comment type.
	 * @param commentType the type of comment to search for.
	 */
	public CommentTypeFilterIterator(CodeUnitIterator it, int commentType) {
		this.it = it;
		this.commentType = commentType;
	}

	/**
	 * @see java.util.Iterator#remove()
	 */
	@Override
	public void remove() {
		throw new UnsupportedOperationException();
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#hasNext()
	 */
	@Override
	public boolean hasNext() {
		if (nextCu == null) {
			findNext();
		}
		return nextCu != null;
	}

	/**
	 * @see ghidra.program.model.listing.CodeUnitIterator#next()
	 */
	@Override
	public CodeUnit next() {
		if (hasNext()) {
			CodeUnit ret = nextCu;
			nextCu = null;
			return ret;
		}
		return null;
	}

	private void findNext() {
		while (it.hasNext()) {
			CodeUnit cu = it.next();
			if (cu.getComment(commentType) != null) {
				nextCu = cu;
				break;
			}
		}
	}

	@Override
	public Iterator<CodeUnit> iterator() {
		return this;
	}

}
