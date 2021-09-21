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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.*;
import ghidra.util.StringUtilities;

public class CommentFieldSearcher extends ProgramDatabaseFieldSearcher {
	private AddressIterator iterator;
	private final int commentType;
	private Program program;

	public CommentFieldSearcher(Program program, ProgramLocation startLoc, AddressSetView set,
			boolean forward, Pattern pattern, int commentType) {

		super(pattern, forward, startLoc, set);
		this.commentType = commentType;
		this.program = program;
		if (set != null) {
			iterator = program.getListing().getCommentAddressIterator(commentType, set, forward);
		}
		else {
			AddressSetView addressSet = program.getMemory();
			if (forward) {
				addressSet.intersectRange(startLoc.getAddress(), addressSet.getMaxAddress());
			}
			else {
				addressSet.intersectRange(addressSet.getMinAddress(), startLoc.getAddress());
			}
			iterator =
				program.getListing().getCommentAddressIterator(commentType, addressSet, forward);
		}
	}

	@Override
	protected Address advance(List<ProgramLocation> currentMatches) {
		Address nextAddress = iterator.next();
		if (nextAddress != null) {
			findMatchesForCurrentAddress(nextAddress, currentMatches);
		}
		return nextAddress;
	}

	private void findMatchesForCurrentAddress(Address address,
			List<ProgramLocation> currentMatches) {
		String comment = program.getListing().getComment(commentType, address);
		if (comment == null) {
			return;
		}
		String cleanedUpComment = comment.replace('\n', ' ');
		Matcher matcher = pattern.matcher(cleanedUpComment);
		while (matcher.find()) {
			int index = matcher.start();
			currentMatches.add(getCommentLocation(comment, index, address));
		}
	}

	private ProgramLocation getCommentLocation(String commentStr, int index, Address address) {
		String[] comments = StringUtilities.toLines(commentStr);
		int rowIndex = findRowIndex(comments, index);
		int charOffset = findCharOffset(index, rowIndex, comments);
		int[] dataPath = getDataComponentPath(address);
		switch (commentType) {
			case CodeUnit.EOL_COMMENT:
				return new EolCommentFieldLocation(program, address, dataPath, comments, rowIndex,
					charOffset, rowIndex);
			case CodeUnit.PLATE_COMMENT:
				return new PlateFieldLocation(program, address, dataPath, rowIndex, charOffset,
					comments, rowIndex);
			case CodeUnit.REPEATABLE_COMMENT:
				return new RepeatableCommentFieldLocation(program, address, dataPath, comments,
					rowIndex, charOffset, rowIndex); // TODO One of searchStrIndex parameters is wrong.
			case CodeUnit.POST_COMMENT:
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

	private int findCharOffset(int index, int rowIndex, String[] opStrings) {
		int totalBeforeOpIndex = 0;
		for (int i = 0; i < rowIndex; i++) {
			totalBeforeOpIndex += opStrings[i].length();
		}
		return index - totalBeforeOpIndex;
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
