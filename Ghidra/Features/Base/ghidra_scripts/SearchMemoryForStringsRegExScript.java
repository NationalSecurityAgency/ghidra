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
//Uses regular expressions to search memory.
//@category Search

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;

import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SearchMemoryForStringsRegExScript extends GhidraScript {

	@Override
	public void run() throws Exception {
		AddressSetView searchSet =
			currentSelection == null ? (AddressSetView) currentProgram.getMemory()
					: currentSelection;

		String regexstr = askString("Regular Expression", "Please enter your regex:");
		Pattern pattern = Pattern.compile(regexstr);

		ArrayList<Address> matchingAddressList = new ArrayList<Address>();

		AddressRangeIterator iter = searchSet.getAddressRanges();

		boolean shouldContinue = true;
		while (iter.hasNext() && !monitor.isCancelled() && shouldContinue) {
			AddressRange range = iter.next();
			monitor.setMessage("Searching ... " + range.getMinAddress() + " to " +
				range.getMaxAddress());

			byte[] bytes = new byte[(int) range.getLength()];
			currentProgram.getMemory().getBytes(range.getMinAddress(), bytes);

			String data = new String(bytes, "ISO-8859-1");
			Matcher matcher = pattern.matcher(data);

			while (!monitor.isCancelled() && matcher.find()) {
				int startIndex = matcher.start();

				Address matchAddress = range.getMinAddress().add(startIndex);
				matchingAddressList.add(matchAddress);

				if (matchingAddressList.size() > 500) {
					popup("More than 500 matches found.");
					shouldContinue = false;
					break;
				}

				if (matchAddress.compareTo(range.getMaxAddress()) >= 0) {
					break;
				}

			}
		}

		if (matchingAddressList.size() == 0) {
			println("No match found");
			return;
		}

		Address[] addrs = new Address[matchingAddressList.size()];
		matchingAddressList.toArray(addrs);
		show(addrs);
	}

}
