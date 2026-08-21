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
package ghidra.app.plugin.core.searchtext.databasesearcher;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.searchtext.Searcher.TextSearchResult;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;

/**
 * Field searcher for comments. Since all comments types for an address are stored in the same
 * database record, comment searchers share a common {@link CommentAddressSupplier} which the
 * overall searcher will manually advance. The advance here will just assume the the comment
 * supplier has been advanced and it will just return the suppliers current address.
 */
public class CommentFieldSearcher extends ProgramDatabaseFieldSearcher {
	private CommentType commentType;
	private CommentAddressSupplier supplier;
	private Program program;

	public CommentFieldSearcher(CommentAddressSupplier supplier, Program program,
			ProgramLocation startLoc,
			AddressSetView set, boolean forward, Pattern pattern, CommentType commentType) {

		super(pattern, forward, startLoc, set);
		this.supplier = supplier;
		this.program = program;
		this.commentType = commentType;
	}

	@Override
	protected Address advance(List<TextSearchResult> currentMatches) {
		Address address = supplier.getCurrentAddress();
		if (address == null) {
			return null;	// we are at the end of the iterator
		}
		findMatchesForCurrentAddress(address, currentMatches);
		return address;
	}

	private void findMatchesForCurrentAddress(Address address,
			List<TextSearchResult> currentMatches) {
		String comment = supplier.getCurrentComment(commentType);
		if (comment == null) {
			return;
		}

		// Remove newlines; turn any annotations into the display version so the screen positions
		// of the program locations work correctly.
		String cleanedUpComment = comment.replaceAll("\n", "");
		String updatedLine = CommentUtils.getDisplayString(cleanedUpComment, program);

		Matcher matcher = pattern.matcher(updatedLine);
		int pos = 0;
		while (matcher.find(pos)) {
			int index = matcher.start();
			ProgramLocation commentLocation = getCommentLocation(comment, index, address);
			currentMatches.add(new TextSearchResult(commentLocation, index));
			pos = index + 1;
		}
	}

	private ProgramLocation getCommentLocation(String commentStr, int index, Address address) {
		String[] comments = StringUtilities.toLines(commentStr);

		int rowIndex = findRowIndex(comments, index);
		int charOffset = getRelativeCharOffset(index, rowIndex, comments);
		int[] dataPath = getDataComponentPath(address);
		switch (commentType) {
			case EOL:
				return new EolCommentFieldLocation(program, address, dataPath, comments, rowIndex,
					charOffset, rowIndex);
			case PLATE:
				return new PlateFieldLocation(program, address, dataPath, rowIndex, charOffset,
					comments, rowIndex);
			case REPEATABLE:
				return new RepeatableCommentFieldLocation(program, address, dataPath, comments,
					rowIndex, charOffset, rowIndex);
			case POST:
				return new PostCommentFieldLocation(program, address, dataPath, comments, rowIndex,
					charOffset);
			default:
				return new CommentFieldLocation(program, address, dataPath, comments, commentType,
					rowIndex, charOffset);
		}

	}

	private int[] getDataComponentPath(Address address) {
		CodeUnit cu = program.getListing().getCodeUnitContaining(address);
		if (cu == null) {
			return null;
		}
		if (cu instanceof Data) {
			Data data = (Data) cu;
			Data primitiveAt = data.getPrimitiveAt((int) address.subtract(data.getAddress()));
			if (primitiveAt != null) {
				return primitiveAt.getComponentPath();
			}
		}
		return null;
	}

	private int getRelativeCharOffset(int index, int rowIndex, String[] comments) {
		int preceding = 0;
		for (int i = 0; i < rowIndex; i++) {
			preceding += comments[i].length();
		}
		return index - preceding;
	}

	private int findRowIndex(String[] commentStrings, int index) {
		int totalSoFar = 0;
		for (int i = 0; i < commentStrings.length; i++) {
			if (index < totalSoFar + commentStrings[i].length()) {
				return i;
			}
			totalSoFar += commentStrings[i].length();
		}
		return commentStrings.length - 1;
	}
}
