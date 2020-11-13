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
package ghidra.feature.fid.service;

import java.util.Map.Entry;

import docking.DockingWindowManager;
import ghidra.feature.fid.plugin.TextAreaDialog;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;

public class DefaultFidPopulateResultReporter implements FidPopulateResultReporter {
	/**
	 * Method to report the results of the ingest task.  Old and crufty, probably needs
	 * to be corrected and updated.
	 * @param result the FID population result
	 */
	@Override
	public void report(FidPopulateResult result) {
		if (result == null) {
			return;
		}

		StringBuilder buffer = new StringBuilder();

		buffer.append(result.getTotalAttempted() + " total functions visited");
		buffer.append("\n");
		buffer.append(result.getTotalAdded() + " total functions added");
		buffer.append("\n");
		buffer.append(result.getTotalExcluded() + " total functions excluded");
		buffer.append("\n");
		buffer.append("Breakdown of exclusions:");
		for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
			if (entry.getKey() != Disposition.INCLUDED) {
				buffer.append("    " + entry.getKey() + ": " + entry.getValue());
				buffer.append("\n");
			}
		}
//		buffer.append("List of unresolved symbols:");
//		buffer.append("\n");
//		TreeSet<String> symbols = new TreeSet<String>();
//		for (Location location : result.getUnresolvedSymbols()) {
//			symbols.add(location.getFunctionName());
//		}
//		for (String symbol : symbols) {
//			buffer.append("    " + symbol);
//			buffer.append("\n");
//		}

		buffer.append("Most referenced functions by name:\n");
		for (FidPopulateResult.Count count : result.getMaxChildReferences()) {
			buffer.append(Integer.toString(count.count));
			buffer.append("  ");
			buffer.append(count.name);
			buffer.append('\n');
		}
		TextAreaDialog dialog =
			new TextAreaDialog("FidDb Popluate Results", buffer.toString(), true);
		DockingWindowManager.showDialog(dialog);
	}

}
