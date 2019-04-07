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
package ghidra.feature.fid.debug;

import java.awt.Font;
import java.util.*;

import javax.swing.*;

import ghidra.feature.fid.db.FidQueryService;
import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.service.FidService;
import ghidra.util.NumericUtilities;

/**
 * Utility class to handle some debug functions for the FID database.
 */
public class FidDebugUtils {
	public static final Font MONOSPACED_FONT = new Font("monospaced", Font.PLAIN, 12);

	/**
	 * Search the FID system for function records by name substring.
	 * @param name the name substring to search
	 */
	public static FidSearchResultFrame searchByName(String name, FidService service,
			FidQueryService fidQueryService) {
		List<FunctionRecord> functionRecords = fidQueryService.findFunctionsByNameSubstring(name);
		return new FidSearchResultFrame("Name: " + name, functionRecords, service, fidQueryService);
	}

	/**
	 * Search the FID system for function records by domain path substring.
	 * @param domainPath the domain path substring to search
	 */
	public static FidSearchResultFrame searchByDomainPath(String domainPath, FidService service,
			FidQueryService fidQueryService) {
		List<FunctionRecord> functionRecords =
			fidQueryService.findFunctionsByDomainPathSubstring(domainPath);
		return new FidSearchResultFrame("Domain Path: " + domainPath, functionRecords, service,
			fidQueryService);
	}

	/**
	 * Search the FID system for function records by exact full hash.
	 * @param fullHash the full hash to search
	 */
	public static FidSearchResultFrame searchByFullHash(long fullHash, FidService service,
			FidQueryService fidQueryService) {
		List<FunctionRecord> functionRecords = fidQueryService.findFunctionsByFullHash(fullHash);
		return new FidSearchResultFrame(String.format("FH: 0x%x", fullHash), functionRecords,
			service, fidQueryService);
	}

	/**
	 * Search the FID system for function records by exact specific hash.
	 * @param specificHash the specific hash to search
	 */
	public static FidSearchResultFrame searchBySpecificHash(long specificHash, FidService service,
			FidQueryService fidQueryService) {
		List<FunctionRecord> functionRecords =
			fidQueryService.findFunctionsBySpecificHash(specificHash);
		return new FidSearchResultFrame(String.format("XH: 0x%x", specificHash), functionRecords,
			service, fidQueryService);
	}

	/**
	 * Opens a function record debug panel in a new window.
	 * @param functionRecord the function record to debug
	 */
	public static void openFunctionWindow(FunctionRecord functionRecord, FidService service,
			FidQueryService fidQueryService) {
		FidFunctionDebugPanel panel =
			new FidFunctionDebugPanel(service, fidQueryService, functionRecord);
		JScrollPane scrollPane = new JScrollPane(panel);

		String title = String.format("0x%x - %s", functionRecord.getID(), functionRecord.getName());
		JFrame frame = new JFrame(title);
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		frame.setContentPane(scrollPane);
		frame.pack();
		frame.setVisible(true);
		fidQueryService.addCloseListener(listener -> frame.dispose());
	}

	/**
	 * Searches for a function by primary key, then pops up a table with the result (or empty).
	 * @param text the string representing the function record primary key
	 */
	public static FidSearchResultFrame searchByFunctionID(long id, FidService service,
			FidQueryService fidQueryService) {
		FunctionRecord functionRecord = fidQueryService.getFunctionByID(id);
		return new FidSearchResultFrame(String.format("Function ID: 0x%x", id),
			functionRecord == null ? new ArrayList<FunctionRecord>()
					: new ArrayList<FunctionRecord>(Collections.singletonList(functionRecord)),
			service, fidQueryService);
	}

	/**
	 * Pops up an error dialog.
	 * @param name the name of the parameter
	 * @param text the text that does not parse as a number
	 */
	private static void popupNumericParseError(String name, String text) {
		JOptionPane.showMessageDialog(null, "Could not parse " + name + ": " + text);
	}

	/**
	 * Tries to parse the text as a long numeric value.
	 * @param text the text to parse
	 * @return the value, or null in case of parse error
	 */
	public static Long validateHashText(String text, String errorMessage) {
		try {
			long parseLong = NumericUtilities.parseLong(text);
			return parseLong;
		}
		catch (NumberFormatException e) {
			popupNumericParseError(errorMessage, text);
			return null;
		}
	}

}
