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
package ghidra.features.base.memsearch.matcher;

import org.apache.commons.collections4.iterators.EmptyIterator;

import ghidra.features.base.memsearch.bytesequence.ExtendedByteSequence;
import ghidra.features.base.memsearch.format.SearchFormat;
import util.CollectionUtils;

/**
 * Objects of this class are the result of {@link SearchFormat}s not being able to fully parse
 * input text. There are two cases. The first is the user type an illegal character for the
 * selected search format. In that case this matcher is both an invalid search and an invalid
 * input and the description will explain the error. The second case is the input is valid text,
 * but not complete so that a fully valid byte matcher could not be created. In this case, the
 * search is still invalid, but the input is valid. The description will reflect this situation.
 */
public class InvalidByteMatcher extends ByteMatcher {

	private final String errorMessage;
	private final boolean isValidInput;

	/**
	 * Construct an invalid matcher from invalid input text.
	 * @param errorMessage the message describing the invalid input
	 */
	public InvalidByteMatcher(String errorMessage) {
		this(errorMessage, false);
	}

	/**
	 * Construct an invalid matcher from invalid input text or partial input text.
	 * @param errorMessage the message describing why this matcher is invalid
	 * @param isValidInput return true if the reason this is invalid is simply that the input
	 * text is not complete. For example, the user types "-" as they are starting to input
	 * a negative number.
	 */
	public InvalidByteMatcher(String errorMessage, boolean isValidInput) {
		super(null, null);
		this.errorMessage = errorMessage;
		this.isValidInput = isValidInput;
	}

	@Override
	public Iterable<ByteMatch> match(ExtendedByteSequence bytes) {
		return CollectionUtils.asIterable(EmptyIterator.emptyIterator());
	}

	@Override
	public String getDescription() {
		return errorMessage;
	}

	@Override
	public String getToolTip() {
		return null;
	}

	@Override
	public boolean isValidInput() {
		return isValidInput;
	}

	@Override
	public boolean isValidSearch() {
		return false;
	}

}
