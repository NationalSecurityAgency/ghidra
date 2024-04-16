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
package docking.dnd;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.List;

public class StringTransferable implements Transferable {
	private static final List<String> STRING_LITERAL_PREFIXES =
		List.of("\"", "u8\"", "u\"", "U\"", "L\"");

	protected String data = null;
	private DataFlavor[] flavors = { DataFlavor.stringFlavor };

	public StringTransferable(String data) {
		this.data = data.replaceAll("\0", "");
	}

	@Override
	public DataFlavor[] getTransferDataFlavors() {
		return flavors;
	}

	@Override
	public boolean isDataFlavorSupported(DataFlavor flavor) {
		return flavor.equals(DataFlavor.stringFlavor);
	}

	@Override
	public Object getTransferData(DataFlavor flavor)
			throws UnsupportedFlavorException, IOException {
		return data;
	}

	/**
	 * Removes quotes and standard string literal prefixes from the string. In order for this 
	 * method to do anything, the string must start with one of the standard string literals
	 * prefixes and end with a quote character"
	 */
	public void removeOuterQuotesAndStandardStringPrefix() {
		if (data.length() < 2 || data.charAt(data.length() - 1) != '"') {
			return;
		}
		for (String prefix : STRING_LITERAL_PREFIXES) {
			if (data.startsWith(prefix)) {
				data = data.substring(prefix.length(), data.length() - 1);
				break;
			}
		}
	}
}
