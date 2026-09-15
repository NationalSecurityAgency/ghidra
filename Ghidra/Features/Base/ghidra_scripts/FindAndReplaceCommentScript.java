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
//This script will replace all comments with values matching the given user search value with the given user replacement value.
//@category Update


import org.apache.commons.lang3.Strings;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;

public class FindAndReplaceCommentScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		Listing listing = currentProgram.getListing();
		Memory memory = currentProgram.getMemory();

		String toFind = askString("Enter Search String", "Search String: ");
		String toReplace = askString("Enter Replace String", "Replace String: ");
		boolean replaced = false;

		AddressIterator commentAddresses = listing.getCommentAddressIterator(memory, true);

		while (commentAddresses.hasNext()) {
			Address address = commentAddresses.next();

			for (CommentType type : CommentType.values()) {
				String commentValue = listing.getComment(type, address);

				if (commentValue != null && commentValue.contains(toFind)) {
					replaced = true;
					listing.setComment(address, type,
						Strings.CS.replace(commentValue, toFind, toReplace));
					printf("\nChanged %s Comment at address %s.\n", type, address.toString());
				}
			}
		}

		if(!replaced) {
			println("No comment found with that value");
		}
	}
}
