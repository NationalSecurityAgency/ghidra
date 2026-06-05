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
package ghidra.features.base.replace.handler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.UpdateCommentQuickFix;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for listing comments on 
 * instructions or data.
 */
public class ListingCommentsSearchAndReplaceHandler extends SearchAndReplaceHandler {

	public ListingCommentsSearchAndReplaceHandler() {
		addType(new SearchType(this, "Comments", "Search and replace in listing comments"));
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		Listing listing = program.getListing();
		long count = listing.getCommentAddressCount();
		monitor.initialize(count, "Searching Comments...");

		Pattern pattern = query.getSearchPattern();
		String replaceMentText = query.getReplacementText();

		for (Address address : listing.getCommentAddressIterator(program.getMemory(), true)) {
			monitor.checkCancelled();
			CodeUnitComments comments = listing.getAllComments(address);
			for (CommentType type : CommentType.values()) {
				String comment = comments.getComment(type);
				String newComment = checkMatch(pattern, comment, replaceMentText);
				if (newComment != null) {
					accumulator.add(
						new UpdateCommentQuickFix(program, address, type, comment, newComment));
				}
			}
		}
	}

	private String checkMatch(Pattern pattern, String comment, String replacementText) {
		if (comment == null) {
			return null;
		}
		Matcher matcher = pattern.matcher(comment);
		if (matcher.find()) {
			return matcher.replaceAll(replacementText);
		}
		return null;
	}
}
