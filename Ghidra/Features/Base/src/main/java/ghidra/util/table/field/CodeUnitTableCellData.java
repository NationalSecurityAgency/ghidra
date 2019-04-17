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
package ghidra.util.table.field;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

/**
 * A class that knows how to render {@link CodeUnit}s in 1 or more lines
 */
public class CodeUnitTableCellData implements Comparable<CodeUnitTableCellData> {

	private final int MAX_LINE_LENGTH = 500;

	private Program program;
	private Address address;

	private CodeUnitFormat formatter;
	private int codeUnitOffset;
	private int codeUnitCount;

	// cached to help sorting performance
	private String displayString;
	private String htmlDisplayString;
	private boolean isOffcut;

	/**
	 * Constructor
	 * 
	 * @param location the location of the code unit to display
	 * @param codeUnitFormat the format needed to render the code unit
	 * @param codeUnitOffset relative code-unit offset from the specified address 
	 * 		   (this is not a byte-offset, it is expressed in terms of number of code-units).
	 * @param codeUnitCount number of code-units to be displayed
	 */
	public CodeUnitTableCellData(ProgramLocation location, CodeUnitFormat codeUnitFormat,
			int codeUnitOffset, int codeUnitCount) {

		if (location == null) {
			throw new AssertException("ProgramLocation cannot be null");
		}

		this.program = location.getProgram();

		if (codeUnitFormat == null) {
			throw new AssertException("CodeUnitFormat cannot be null");
		}

		this.formatter = codeUnitFormat;
		this.codeUnitOffset = codeUnitOffset;
		this.codeUnitCount = codeUnitCount;
		this.address = location.getByteAddress();
	}

	@Override
	public String toString() {
		return getDisplayString(); // a nice default
	}

	@Override
	public int compareTo(CodeUnitTableCellData data) {
		return getDisplayString().compareTo(data.getDisplayString());
	}

	/**
	 * Get the visual representation for the code unit at or containing the address 
	 * associated with this cell's row
	 * 
	 * @return the display string
	 */
	public String getDisplayString() {
		if (displayString != null) {
			return displayString;
		}
		displayString = createDisplayString(false);
		return displayString;
	}

	/**
	 * Get the visual representation as HTML for the code unit at or containing the 
	 * address associated with this cell's row
	 * 
	 * @return the display string
	 */
	public String getHTMLDisplayString() {
		if (htmlDisplayString == null) {
			htmlDisplayString = "<html><pre>" + createDisplayString(true) + "</pre></html>";
		}
		return htmlDisplayString;
	}

	public List<String> getDisplayStrings() {
		return getDisplayLines(false);
	}

	public boolean isOffcut() {
		return isOffcut;
	}

	private String getDataPath(Data data) {
		String path = data.getComponentPathName();
		int dotIndex = path.indexOf(".");
		if (dotIndex != -1) {
			path = path.substring(dotIndex + 1);
		}

		Data parent = data.getParent();
		DataType parentType = parent.getDataType();

		String separator = ".";
		if (parentType instanceof Array) {
			separator = "";
		}

		return " (" + parentType.getName() + separator + path + ")";
	}

	private CodeUnit getCodeUnitContaining(Address addr) {
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitAt(addr);
		if (cu == null) {
			cu = listing.getCodeUnitContaining(addr);
			if (cu instanceof Data) {
				Data data = (Data) cu;
				return data.getPrimitiveAt((int) addr.subtract(data.getMinAddress()));
			}
		}
		return cu;
	}

	private CodeUnit getCodeUnitBefore(CodeUnit cu) {
		if (cu != null) {
			try {
				return getCodeUnitContaining(cu.getMinAddress().subtractNoWrap(1));
			}
			catch (AddressOverflowException e) {
				// don't care; we really want null in this case
			}
		}
		return null;
	}

	private CodeUnit getCodeUnitAfter(CodeUnit cu) {
		if (cu != null) {
			try {
				return getCodeUnitContaining(cu.getMaxAddress().addNoWrap(1));
			}
			catch (AddressOverflowException e) {
				// don't care; we really want null in this case
			}
		}
		return null;
	}

	private String createDisplayString(boolean htmlFriendly) {
		List<String> lines = getDisplayLines(htmlFriendly);
		StringBuilder buffy = new StringBuilder();
		for (int i = 0; i < lines.size(); i++) {
			String string = lines.get(i);
			buffy.append(string);
			if (i < lines.size() - 1) {
				buffy.append("\n");
			}
		}
		return buffy.toString();
	}

	private List<String> getDisplayLines(boolean htmlFriendly) {
		List<String> lines = new ArrayList<>();

		if (address.isExternalAddress()) {
			return lines;
		}

		int codeUnitStart = codeUnitOffset;
		int codeUnitEnd = codeUnitStart + codeUnitCount - 1;

		CodeUnit containingCodeUnit = getCodeUnitContaining(address);
		CodeUnit codeUnit = containingCodeUnit;

		int codeUnitIndex = 0;
		int count = 0;
		if (codeUnitStart <= 0 && codeUnitEnd >= 0) {
			lines.add(createDisplayString(codeUnit, formatter, htmlFriendly));
			++count;
		}

		while (count < codeUnitCount) {

			// Get next code unit
			if (codeUnitIndex <= 0) {
				if (codeUnitIndex <= codeUnitStart) {
					// switch to the forward direction
					codeUnit = containingCodeUnit;
					codeUnitIndex = 0;
				}
				else {
					// check previous code unit
					codeUnit = getCodeUnitBefore(codeUnit);
					--codeUnitIndex;
				}
			}
			if (codeUnitIndex >= 0) {
				// check next code unit
				codeUnit = getCodeUnitAfter(codeUnit);
				++codeUnitIndex;
			}

			// Generate code-unit representation if needed
			if (codeUnitIndex >= codeUnitStart && codeUnitIndex <= codeUnitEnd) {
				String display = createDisplayString(codeUnit, formatter, htmlFriendly);
				if (codeUnitIndex < 0) {
					lines.add(0, display);
				}
				else {
					lines.add(display);
				}
				++count;
			}
		}

		return lines;
	}

	private String createDisplayString(CodeUnit cu, CodeUnitFormat cuFormat, boolean htmlFriendly) {
		String representation = null;
		if (cu != null) {
			representation = createCodeUnitRepresentation(cu, cuFormat);
		}
		if (representation == null || representation.length() == 0) {
			representation = "??";
		}

		if (htmlFriendly) {
			if (representation.length() > MAX_LINE_LENGTH) {
				representation = representation.substring(0, MAX_LINE_LENGTH);
			}

			representation = HTMLUtilities.friendlyEncodeHTML(representation);
		}

		return representation;
	}

	private String createCodeUnitRepresentation(CodeUnit cu, CodeUnitFormat cuFormat) {
		if (!(cu instanceof Data)) {
			return cuFormat.getRepresentationString(cu);
		}

		Data data = (Data) cu;
		String representation = cuFormat.getRepresentationString(data);
		if (data.getParent() != null) {
			String path = getDataPath(data);
			if (!path.equals(representation)) {
				representation += path;
			}
		}

		return representation;
	}
}
