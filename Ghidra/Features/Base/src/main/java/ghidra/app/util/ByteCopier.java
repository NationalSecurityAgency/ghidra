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
package ghidra.app.util;

import java.awt.datatransfer.*;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.dnd.GenericDataFlavor;
import docking.dnd.StringTransferable;
import docking.widgets.OptionDialog;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.MemoryByteIterator;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;

/**
 * Base class that can copy bytes into a Transferable object, and paste
 * bytes into a program.
 *
 */
public abstract class ByteCopier {

	public static DataFlavor BYTE_STRING_FLAVOR = createByteStringLocalDataTypeFlavor();
	public static DataFlavor BYTE_STRING_NO_SPACES_FLAVOR =
		createByteStringNoSpacesLocalDataTypeFlavor();
	public static DataFlavor PYTHON_BYTE_STRING_FLAVOR =
		createPythonByteStringLocalDataTypeFlavor();
	public static DataFlavor PYTHON_LIST_FLAVOR = createPythonListLocalDataTypeFlavor();
	public static DataFlavor CPP_BYTE_ARRAY_FLAVOR =
		createCppByteArrayLocalDataTypeFlavor();

	protected static final List<ClipboardType> EMPTY_LIST = Collections.emptyList();
	public static final ClipboardType BYTE_STRING_TYPE =
		new ClipboardType(BYTE_STRING_FLAVOR, "Byte String");
	public static final ClipboardType BYTE_STRING_NO_SPACE_TYPE =
		new ClipboardType(BYTE_STRING_NO_SPACES_FLAVOR, "Byte String (No Spaces)");
	public static final ClipboardType PYTHON_BYTE_STRING_TYPE =
		new ClipboardType(PYTHON_BYTE_STRING_FLAVOR, "Python Byte String");
	public static final ClipboardType PYTHON_LIST_TYPE =
		new ClipboardType(PYTHON_LIST_FLAVOR, "Python List");
	public static final ClipboardType CPP_BYTE_ARRAY_TYPE =
		new ClipboardType(CPP_BYTE_ARRAY_FLAVOR, "C Array");

	private static final Map<DataFlavor, Pattern> PROGRAMMING_PATTERNS_BY_FLAVOR =
		Map.of(
			PYTHON_BYTE_STRING_FLAVOR, Pattern.compile("b'(.*)'"),
			PYTHON_LIST_FLAVOR, Pattern.compile("\\[(.*)\\]"),
			CPP_BYTE_ARRAY_FLAVOR, Pattern.compile("\\{(.*)\\}"));

	/**
	 * Pattern to recognize bytes that have been encoded during a copy operation using one of this
	 * class's programming copy types
	 */
	private static final Pattern PROGRAMMING_BYTES_PATTERN =
		Pattern.compile("(?:\\\\x|0x)([a-fA-F0-9]{2})");

	private static DataFlavor createByteStringLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--byte string with spaces");
		}
		catch (Exception e) {
			Msg.error(ByteCopier.class,
				"Unexpected exception creating data flavor for byte string", e);
		}

		return null;
	}

	private static DataFlavor createByteStringNoSpacesLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--byte string with NO spaces");
		}
		catch (Exception e) {
			Msg.error(ByteCopier.class,
				"Unexpected exception creating data flavor for byte string with no spaces", e);
		}

		return null;
	}

	private static DataFlavor createPythonByteStringLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--Python byte string");
		}
		catch (Exception e) {
			Msg.error(ByteCopier.class,
				"Unexpected exception creating data flavor for Python byte string", e);
		}

		return null;
	}

	private static DataFlavor createPythonListLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--Python list");
		}
		catch (Exception e) {
			Msg.error(ByteCopier.class,
				"Unexpected exception creating data flavor for Python list", e);
		}

		return null;
	}

	private static DataFlavor createCppByteArrayLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--C++ array");
		}
		catch (Exception e) {
			Msg.error(ByteCopier.class,
				"Unexpected exception creating data flavor for C array", e);
		}

		return null;
	}

	protected PluginTool tool;
	protected Program currentProgram;
	protected ProgramSelection currentSelection;
	protected ProgramLocation currentLocation;

	protected ByteCopier() {
		// limit construction
	}

	protected AddressSetView getSelectedAddresses() {
		AddressSetView addressSet = currentSelection;
		if (addressSet == null || addressSet.isEmpty()) {
			return new AddressSet(currentLocation.getAddress());
		}
		return currentSelection;
	}

	protected Transferable copyBytes(AddressSetView addresses, boolean includeSpaces,
			TaskMonitor monitor) {
		return createStringTransferable(copyBytesAsString(addresses, includeSpaces, monitor));
	}

	protected String copyBytesAsString(AddressSetView addresses, boolean includeSpaces,
			TaskMonitor monitor) {

		String delimiter = includeSpaces ? " " : "";
		return copyBytesAsString(addresses, delimiter, monitor);
	}

	protected String copyBytesAsString(AddressSetView addresses, String delimiter,
			TaskMonitor monitor) {

		Memory memory = currentProgram.getMemory();
		ByteIterator bytes = new ByteIterator(addresses, memory);
		return NumericUtilities.convertBytesToString(bytes, delimiter);
	}

	private byte[] getBytes(String transferString) {

		byte[] bytes = getHexBytes(transferString);
		if (bytes != null) {
			return bytes;
		}

		// maybe the text is ascii?
		return getAsciiBytes(transferString);
	}

	private byte[] getAsciiBytes(String s) {

		byte[] bytes = new byte[s.length()];
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (!StringUtilities.isAsciiChar(c)) {
				return null;
			}
			bytes[i] = (byte) c;
		}

		return bytes;
	}

	private String keepOnlyAsciiBytes(String s) {

		byte[] bytes = new byte[s.length()];
		int byteIndex = 0;
		for (int stringIndex = 0; stringIndex < s.length(); stringIndex++) {
			char c = s.charAt(stringIndex);
			if (!StringUtilities.isAsciiChar(c)) {
				continue;
			}
			bytes[byteIndex++] = (byte) c;
		}

		return new String(bytes, 0, byteIndex);
	}

	private boolean isOnlyAsciiBytes(String s) {

		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (!StringUtilities.isAsciiChar(c)) {
				return false;
			}
		}

		return true;
	}

	private byte[] getHexBytes(String s) {
		s = s.trim().replaceAll("\\s", "");
		int length = s.length();
		if (length % 2 != 0) {
			return null; // even number of hex nibbles required for raw bytes
		}

		try {
			byte[] data = new byte[length / 2];
			int cindex = 0;
			for (int i = 0; i < data.length; i++) {
				String byteStr = s.substring(cindex, cindex + 2);
				data[i] = (byte) Integer.parseInt(byteStr, 16);
				cindex += 2;
			}
			return data;
		}
		catch (Exception e) {
			// return null to signal an error condition
		}
		return null;
	}

	protected Transferable copyBytes(ClipboardType copyType, TaskMonitor monitor) {

		if (copyType == BYTE_STRING_TYPE) {
			String byteString = copyBytesAsString(getSelectedAddresses(), true, monitor);
			return new ByteStringTransferable(byteString);
		}
		else if (copyType == BYTE_STRING_NO_SPACE_TYPE) {
			String byteString = copyBytesAsString(getSelectedAddresses(), false, monitor);
			return new ByteStringTransferable(byteString);
		}
		else if (copyType == PYTHON_BYTE_STRING_TYPE) {
			String prefix = "\\x";
			String bs = copyBytesAsString(getSelectedAddresses(), prefix, monitor);
			String fixed = "b'" + prefix + bs + "'";
			return new ProgrammingByteStringTransferable(fixed, copyType.getFlavor());
		}
		else if (copyType == PYTHON_LIST_TYPE) {
			String prefix = "0x";
			String bs = copyBytesAsString(getSelectedAddresses(), ", " + prefix, monitor);
			String fixed = "[ " + prefix + bs + " ]";
			return new ProgrammingByteStringTransferable(fixed, copyType.getFlavor());
		}
		else if (copyType == CPP_BYTE_ARRAY_TYPE) {
			String prefix = "0x";
			String bs = copyBytesAsString(getSelectedAddresses(), ", " + prefix, monitor);
			String byteString = "{ " + prefix + bs + " }";
			return new ProgrammingByteStringTransferable(byteString, copyType.getFlavor());
		}

		return null;
	}

	protected boolean pasteBytes(Transferable pasteData)
			throws UnsupportedFlavorException, IOException {

		DataFlavor[] flavors = pasteData.getTransferDataFlavors();
		DataFlavor byteStringFlavor = getByteStringFlavor(flavors);
		if (byteStringFlavor != null) {
			String data = (String) pasteData.getTransferData(byteStringFlavor);
			return pasteByteString(data);
		}

		DataFlavor programmingFlavor = getProgrammingFlavor(flavors);
		if (programmingFlavor != null) {
			String data = (String) pasteData.getTransferData(programmingFlavor);
			String byteString = extractProgrammingBytes(programmingFlavor, data);
			if (byteString != null) {
				return pasteByteString(byteString);
			}
		}

		if (!pasteData.isDataFlavorSupported(DataFlavor.stringFlavor)) {
			tool.setStatusInfo("Paste failed: unsupported data type", true);
			return false;
		}

		// see if the pasted data is similar to other known programming formats
		String string = (String) pasteData.getTransferData(DataFlavor.stringFlavor);
		if (string == null) {
			tool.setStatusInfo("Paste failed: no string data", true);
			return false;
		}

		return pasteByteString(string);
	}

	private DataFlavor getProgrammingFlavor(DataFlavor[] flavors) {
		for (DataFlavor flavor : flavors) {
			if (flavor.equals(PYTHON_BYTE_STRING_FLAVOR) ||
				flavor.equals(PYTHON_LIST_FLAVOR) ||
				flavor.equals(CPP_BYTE_ARRAY_FLAVOR)) {
				return flavor;
			}
		}
		return null;
	}

	private DataFlavor getByteStringFlavor(DataFlavor[] flavors) {

		for (DataFlavor flavor : flavors) {
			if (flavor.equals(BYTE_STRING_FLAVOR) ||
				flavor.equals(BYTE_STRING_NO_SPACES_FLAVOR)) {
				return flavor;
			}
		}

		return null;
	}

	private String extractProgrammingBytes(DataFlavor flavor, String data) {

		Pattern pattern = PROGRAMMING_PATTERNS_BY_FLAVOR.get(flavor);
		Matcher matcher = pattern.matcher(data);
		if (!matcher.matches()) {
			return null;
		}

		String bytes = matcher.group(1);
		if (bytes == null) {
			return null;
		}

		Matcher bytesMatcher = PROGRAMMING_BYTES_PATTERN.matcher(bytes);
		if (!bytesMatcher.find()) {
			return null;
		}

		StringBuilder buffy = new StringBuilder();
		buffy.append(bytesMatcher.group(1));
		while (bytesMatcher.find()) {
			buffy.append(bytesMatcher.group(1));
		}
		return buffy.toString();
	}

	protected boolean pasteByteString(final String string) {
		Command cmd = new Command() {

			private String status = "Pasting";

			@Override
			public boolean applyTo(DomainObject domainObject) {
				if (!(domainObject instanceof Program)) {
					return false;
				}

				String validString = string;
				if (!isOnlyAsciiBytes(string)) {
					tool.setStatusInfo("Pasted string contained non-text ascii bytes. " +
						"Only the ascii will be used.", true);
					validString = keepOnlyAsciiBytes(string);
				}

				byte[] bytes = getBytes(validString);
				if (bytes == null) {
					status = "Improper data format. Expected sequence of hex bytes";
					tool.beep();
					return false;
				}

				// Ensure that we are not writing over instructions
				Program program = (Program) domainObject;
				Address address = currentLocation.getAddress();
				if (!hasEnoughSpace(program, address, bytes.length)) {
					status =
						"Not enough space to paste all bytes.  Encountered data or instructions.";
					tool.beep();
					return false;
				}

				// Ask the user before pasting a string into the program.  Since having a string in 
				// the clipboard is so common, this is to prevent an accidental paste.
				if (!confirmPaste(validString)) {
					return true; // the user cancelled; the command is successful
				}

				boolean pastedAllBytes = pasteBytes(program, bytes);
				if (!pastedAllBytes) {
					tool.setStatusInfo("Not all bytes were pasted due to memory access issues",
						true);
				}

				return true;
			}

			private boolean pasteBytes(Program program, byte[] bytes) {

				// note: loop one byte at a time here, since Memory will validate all addresses
				//       before pasting any bytes
				boolean foundError = false;
				Address address = currentLocation.getAddress();
				Memory memory = program.getMemory();
				for (byte element : bytes) {
					try {
						memory.setByte(address, element);
					}
					catch (MemoryAccessException e) {
						// Keep trying the remaining bytes.  Should we just stop in this case?
						foundError = true;
					}
					address = address.next();
				}
				return foundError;
			}

			private boolean confirmPaste(String validString) {

				// create a truncated version of the string to show in the dialog
				String partialText = validString.length() < 40 ? validString
						: validString.substring(0, 40) + " ...";
				int result = OptionDialog.showYesNoDialog(null, "Paste String Into Program?",
					"Are you sure you want to paste the string \"" + partialText +
						"\"\n into the program's memory?");

				return result != OptionDialog.NO_OPTION;
			}

			private boolean hasEnoughSpace(Program program, Address address, int byteCount) {
				Listing listing = program.getListing();
				for (int i = 0; i < byteCount;) {
					if (address == null) {
						status = "Not enough addresses to paste bytes";
						tool.beep();
						return false;
					}
					CodeUnit codeUnit = listing.getCodeUnitContaining(address);
					if (!(codeUnit instanceof Data) || ((Data) codeUnit).isDefined()) {
						status = "Cannot paste on top of defined instructions/data";
						tool.beep();
						return false;
					}
					int length = codeUnit.getLength();
					i += length;
					address = codeUnit.getMaxAddress().next();
				}
				return true;
			}

			@Override
			public String getStatusMsg() {
				return status;
			}

			@Override
			public String getName() {
				return "Paste";
			}

		};

		return tool.execute(cmd, currentProgram);
	}

	/**
	 * Create a Transferable from the given text.
	 * @param text text used to create a Transferable
	 * @return a Transferable
	 */
	public static Transferable createStringTransferable(String text) {
		return new StringTransferable(text);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * An iterator of bytes from memory.  This class exists because the {@link MemoryByteIterator}
	 * throws an exception from its next() method, which will not work for us.
	 */
	private static class ByteIterator implements Iterator<Byte> {

		private MemoryByteIterator byteIterator;
		private Byte next;

		ByteIterator(AddressSetView addresses, Memory memory) {
			byteIterator = new MemoryByteIterator(memory, addresses);
		}

		@Override
		public boolean hasNext() {

			if (next != null) {
				return true;
			}

			if (!byteIterator.hasNext()) {
				return false;
			}

			try {
				next = byteIterator.next();
			}
			catch (MemoryAccessException e) {
				Msg.error(this, "Unable to read next byte", e);
				return false;
			}
			return true;
		}

		@Override
		public Byte next() {

			if (next == null) {
				throw new NoSuchElementException();
			}

			Byte result = next;
			next = null;
			return result;
		}
	}

	public static class ProgrammingByteStringTransferable implements Transferable {

		private List<DataFlavor> flavorList;
		private DataFlavor[] flavors;
		private DataFlavor programmingFlavor;
		private String byteString;

		public ProgrammingByteStringTransferable(String byteString, DataFlavor flavor) {
			this.byteString = byteString;
			this.programmingFlavor = flavor;
			this.flavors = new DataFlavor[] { flavor, DataFlavor.stringFlavor };
			this.flavorList = Arrays.asList(flavors);
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (flavor.equals(DataFlavor.stringFlavor)) {
				return byteString; // just default to the byte string when no 'special' string data
			}
			if (flavor.equals(programmingFlavor)) {
				return byteString;
			}
			throw new UnsupportedFlavorException(flavor);
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return flavors;
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return flavorList.contains(flavor);
		}
	}

	public static class ByteStringTransferable implements Transferable {

		private final DataFlavor[] flavors = {
			BYTE_STRING_NO_SPACE_TYPE.getFlavor(),
			BYTE_STRING_TYPE.getFlavor(),
			DataFlavor.stringFlavor };
		private final List<DataFlavor> flavorList = Arrays.asList(flavors);

		private final String byteString;
		private final String stringRepresentation;

		public ByteStringTransferable(String byteString) {
			this(byteString, null);
		}

		public ByteStringTransferable(String byteString, String stringRepresentation) {
			this.byteString = byteString;
			this.stringRepresentation = stringRepresentation;
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (flavor.equals(DataFlavor.stringFlavor)) {
				if (stringRepresentation != null) {
					return stringRepresentation;
				}
				return byteString; // just default to the byte string when no 'special' string data
			}
			if (flavor.equals(BYTE_STRING_TYPE.getFlavor())) {
				return byteString;
			}
			if (flavor.equals(BYTE_STRING_NO_SPACE_TYPE.getFlavor())) {
				return byteString;
			}
			throw new UnsupportedFlavorException(flavor);
		}

		@Override
		public DataFlavor[] getTransferDataFlavors() {
			return flavors;
		}

		@Override
		public boolean isDataFlavorSupported(DataFlavor flavor) {
			return flavorList.contains(flavor);
		}

	}
}
