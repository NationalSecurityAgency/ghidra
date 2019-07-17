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
package ghidra.util.table;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.util.*;
import ghidra.util.HTMLUtilities;
import ghidra.util.exception.AssertException;

/**
 * A generic data type used by table models in order to signal that the data should render
 * a preview for a given {@link ProgramLocation}, where the preview is what is displayed in 
 * the Listing.
 */
public class PreviewTableCellData implements Comparable<PreviewTableCellData> {

	private final int MAX_LINE_LENGTH = 500;
	private final Address address;
	private final ProgramLocation location;
	private final Program program;
	private CodeUnitFormat formatter;

	// cached preview to help sorting performance
	private String displayString;
	private String htmlDisplayString;
	private boolean isOffcut;

	/**
	 * Constructor
	 * 
	 * @param location the location for the preview
	 * @param codeUnitFormat the format needed to render preview data
	 */
	public PreviewTableCellData(ProgramLocation location, CodeUnitFormat codeUnitFormat) {

		if (location == null) {
			throw new AssertException("ProgramLocation cannot be null");
		}

		this.location = location;
		this.program = location.getProgram();
		if (program == null) {
			throw new AssertException("Program cannot be null");
		}

		if (codeUnitFormat == null) {
			throw new AssertException("CodeUnitFormat cannot be null");
		}

		this.formatter = codeUnitFormat;
		this.address = location.getByteAddress();
		isOffcut = determineIsOffcut();
	}

	private boolean determineIsOffcut() {
		if (address.isExternalAddress()) {
			return false;
		}
		Listing listing = program.getListing();
		CodeUnit cu = listing.getCodeUnitContaining(address);
		if (cu == null) {
			return false;
		}
		if (cu instanceof Data) {
			Data data = (Data) cu;
			data = data.getPrimitiveAt((int) address.subtract(data.getMinAddress()));
			if (data != null) {
				return !data.getMinAddress().equals(address);
			}
		}
		return !cu.getMinAddress().equals(address);
	}

	public boolean isOffcut() {
		return isOffcut;
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

	private String getPreview(CodeUnit cu, boolean htmlFriendly) {
		String preview = getFormatedCodeUnitPreview(cu);
		if (preview == null || preview.length() == 0) {
			preview = "??";
		}

		if (htmlFriendly) {
			if (preview.length() > MAX_LINE_LENGTH) {
				preview = preview.substring(0, MAX_LINE_LENGTH);
			}

			preview = HTMLUtilities.friendlyEncodeHTML(preview);
		}

		return preview;
	}

	private String getCodeUnitPreview(CodeUnitFormat format) {
		Address addr = location.getAddress();
		if (addr.isExternalAddress()) {
			Symbol s = program.getSymbolTable().getPrimarySymbol(addr);
			if (s != null) {
				ExternalLocation extLoc = program.getExternalManager().getExternalLocation(s);
				DataType dt = extLoc.getDataType();
				if (dt == null) {
					dt = DataType.DEFAULT;
				}
				return dt.getMnemonic(dt.getDefaultSettings());
			}
		}

		CodeUnit cu = program.getListing().getCodeUnitAt(addr);
		return getFormatedCodeUnitPreview(cu);
	}

	private String getFormatedCodeUnitPreview(CodeUnit cu) {

		if (cu == null) {
			return null;
		}

		if (!(cu instanceof Data)) {
			return formatter.getRepresentationString(cu);
		}

		Data data = (Data) cu;
		String preview = formatter.getRepresentationString(data);
		if (data.getParent() != null) {
			String path = getDataPath(data);
			if (!path.equals(preview)) {
				preview += path;
			}
		}

		return preview;
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

	private String getPreview(boolean htmlFriendly) {
		String preview = getProgramLocationPreview();
		if (preview != null) {
			return preview;
		}

		// nothing special for the given location, just display the code unit
		// Note: this will change over time as we add more program-location-specific previews
		CodeUnit codeUnit = getCodeUnitContaining(address);
		if (codeUnit != null) {
			return getPreview(codeUnit, htmlFriendly);
		}

		// Note: at the time of writing, this code will never be executed, as the CodeManager
		// will always return a CodeUnit, even when there is nothing in the database
		return getAddressPreview();
	}

	private String getAddressPreview() {
		if (address.isExternalAddress()) {
			Symbol s = program.getSymbolTable().getPrimarySymbol(address);
			if (s != null) {
				ExternalLocation loc = program.getExternalManager().getExternalLocation(s);
				DataType dt = loc.getDataType();
				if (dt == null) {
					dt = DataType.DEFAULT;
				}
				return dt.getMnemonic(dt.getDefaultSettings());
			}
		}

		return null;
	}

	/**
	 * Get the preview for the code unit at or containing the address associated with this cell's row.
	 * 
	 * @return the preview string.
	 */
	public String getDisplayString() {
		if (displayString != null) {
			return displayString;
		}
		displayString = getPreview(false);
		return displayString;
	}

	@Override
	public String toString() {
		return getDisplayString(); // a nice default
	}

	/**
	 * Get the preview as HTML for the code unit at or containing the address associated with this cell's row.
	 * 
	 * @return the preview string.
	 */
	public String getHTMLDisplayString() {
		if (htmlDisplayString == null) {
			htmlDisplayString = "<html><pre>" + getPreview(true) + "</pre></html>";
		}
		return htmlDisplayString;
	}

	public ProgramLocation getProgramLocation() {
		return location;
	}

	@Override
	public int compareTo(PreviewTableCellData data) {
		return getDisplayString().compareTo(data.getDisplayString());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private String getProgramLocationPreview() {

		if (location instanceof FunctionSignatureFieldLocation) {
			return ((FunctionSignatureFieldLocation) location).getSignature();
		}

		if (location instanceof FunctionRepeatableCommentFieldLocation) {
			return getFunctionCommentPreview((FunctionRepeatableCommentFieldLocation) location);
		}

		if (location instanceof VariableLocation) {
			return getVariablePreview((VariableLocation) location);
		}

		if (location instanceof LabelFieldLocation) {
			return ((LabelFieldLocation) location).getName();
		}

		if ((location instanceof MnemonicFieldLocation) ||
			(location instanceof OperandFieldLocation)) {
			return getCodeUnitPreview(formatter);
		}

		if (location instanceof CommentFieldLocation) {
			return getCommentPreview((CommentFieldLocation) location);
		}

		return null;
	}

	private String getVariablePreview(VariableLocation loc) {
		if (loc instanceof VariableCommentFieldLocation) {
			return ((VariableCommentFieldLocation) loc).getComment();
		}

		Variable var = loc.getVariable();
		if (var == null) {
			return ""; // must no longer be a valid variable location
		}

		String comments = var.getComment();
		StringBuilder sb = new StringBuilder();

		DataType dt = var.getDataType();
		String dtName = "Unknown";
		if (dt != null) {
			dtName = dt.getDisplayName();
		}
		sb.append(dtName);
		sb.append(" ");
		sb.append(var.getVariableStorage().toString());
		sb.append(" ");
		sb.append(var.getName());
		if (comments != null) {
			sb.append(" ");
			sb.append(comments);
		}
		return sb.toString();
	}

	private String getCommentPreview(CommentFieldLocation loc) {
		String[] comment = loc.getComment();
		int row = loc.getRow();
		if (row >= 0 && row < comment.length) {
			return comment[row];
		}
		return "";
	}

	private String getFunctionCommentPreview(FunctionRepeatableCommentFieldLocation loc) {
		String[] comment = loc.getComment();
		int row = loc.getRow();
		if (row >= 0 && row < comment.length) {
			return comment[row];
		}
		return "";
	}
}
