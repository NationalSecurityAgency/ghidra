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

import docking.dnd.GenericDataFlavor;
import docking.dnd.StringTransferable;
import docking.widgets.OptionDialog;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
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

	private static DataFlavor createByteStringLocalDataTypeFlavor() {

		try {
			return new GenericDataFlavor(
				DataFlavor.javaJVMLocalObjectMimeType + "; class=java.lang.String",
				"Local flavor--byte string with spaces");
		}
		catch (Exception e) {
			Msg.showError(ByteCopier.class, null, "Could Not Create Data Flavor",
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
			Msg.showError(ByteCopier.class, null, "Could Not Create Data Flavor",
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
			Msg.showError(ByteCopier.class, null, "Could Not Create Data Flavor",
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
			Msg.showError(ByteCopier.class, null, "Could Not Create Data Flavor",
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
			Msg.showError(ByteCopier.class, null, "Could Not Create Data Flavor",
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

	protected Transferable copyBytes(boolean includeSpaces, TaskMonitor monitor) {
		return copyBytes(currentSelection, includeSpaces, monitor);
	}

	protected Transferable copyBytes(AddressSetView addresses, boolean includeSpaces,
			TaskMonitor monitor) {
		return createStringTransferable(copyBytesAsString(addresses, includeSpaces, monitor));
	}

	protected String copyBytesAsString(AddressSetView addresses, boolean includeSpaces,
			TaskMonitor monitor) {

		Memory memory = currentProgram.getMemory();
		String delimiter = includeSpaces ? " " : "";
		ByteIterator bytes = new ByteIterator(addresses, memory);
		return NumericUtilities.convertBytesToString(bytes, delimiter);
	}

	protected boolean supportsPasteTransferable(Transferable transferable) {
		return isValidBytesTransferable(transferable);
	}

	protected boolean isValidBytesTransferable(Transferable transferable) {

		DataFlavor[] flavors = transferable.getTransferDataFlavors();
		for (DataFlavor element : flavors) {

			try {
				Object object = transferable.getTransferData(element);
				if (object instanceof String) {
					String string = (String) object;
					if (!isOnlyAsciiBytes(string)) {
						tool.setStatusInfo("Paste string contains non-text ascii bytes. " +
							"Only the ascii text will be pasted.", true);

						string = keepOnlyAsciiBytes(string);
					}
					return (getBytes(string) != null);
				}
			}
			catch (Exception e) {
				// don't care; try the next one
			}
		}

		return false;
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

	protected boolean pasteBytes(Transferable pasteData)
			throws UnsupportedFlavorException, IOException {
		if (!supportsPasteTransferable(pasteData)) {
			tool.setStatusInfo("Paste failed: No valid data on clipboard", true);
			return false;
		}

		if (pasteData.isDataFlavorSupported(BYTE_STRING_FLAVOR)) {
			String data = (String) pasteData.getTransferData(BYTE_STRING_FLAVOR);
			return pasteByteString(data);
		}

		if (pasteData.isDataFlavorSupported(BYTE_STRING_NO_SPACES_FLAVOR)) {
			String data = (String) pasteData.getTransferData(BYTE_STRING_NO_SPACES_FLAVOR);
			return pasteByteString(data);
		}

		String string = (String) pasteData.getTransferData(DataFlavor.stringFlavor);
		return pasteByteString(string);
	}

	protected boolean pasteByteString(final String string) {
		Command cmd = new Command() {

			private String status = "Pasting";

			@Override
			public boolean applyTo(DomainObject domainObject) {
				if (domainObject instanceof Program) {
					String validString = string;
					if (!isOnlyAsciiBytes(string)) {
						tool.setStatusInfo("Pasted string contained non-text ascii bytes. " +
							"Only the ascii text was pasted.", true);

						validString = keepOnlyAsciiBytes(string);
					}

					byte[] bytes = getBytes(validString);
					if (bytes == null) {
						status = "Improper data format (expected sequence of hex bytes)";
						tool.beep();
						return false;
					}

					// Ensure that we are not writing over instructions
					Program curProgram = (Program) domainObject;
					Listing listing = curProgram.getListing();
					Address curAddr = currentLocation.getAddress();
					int byteCount = bytes.length;
					for (int i = 0; i < byteCount;) {
						if (curAddr == null) {
							status = "Not enough addresses to paste bytes";
							tool.beep();
							return false;
						}
						CodeUnit curCodeUnit = listing.getCodeUnitContaining(curAddr);
						if (!(curCodeUnit instanceof Data) || ((Data) curCodeUnit).isDefined()) {
							status = "Cannot paste on top of defined instructions/data";
							tool.beep();
							return false;
						}
						int length = curCodeUnit.getLength();
						i += length;
						curAddr = curCodeUnit.getMaxAddress().next();
					}

					// Per SCR 11212, ask the user before pasting a string into the program.
					// Since having a string in the clipboard is so common, this is to prevent
					// an accidental paste.

					// create a truncated version of the string to show in the dialog
					String partialText = validString.length() < 40 ? validString
							: validString.substring(0, 40) + " ...";

					int result = OptionDialog.showYesNoDialog(null, "Paste String Into Program?",
						"Are you sure you want to paste the string \"" + partialText +
							"\"\n into the program's memory?");

					if (result == OptionDialog.NO_OPTION) {
						return true;
					}

					// Write data
					curAddr = currentLocation.getAddress();
					for (byte element : bytes) {
						try {
							curProgram.getMemory().setByte(curAddr, element);
						}
						catch (MemoryAccessException e1) {
							// handle below
						}
						curAddr = curAddr.next();
					}

					return true;
				}
				return false;
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

	public static class ByteViewerTransferable implements Transferable {

		private final DataFlavor[] flavors = { BYTE_STRING_NO_SPACE_TYPE.getFlavor(),
			BYTE_STRING_TYPE.getFlavor(), PYTHON_BYTE_STRING_TYPE.getFlavor(),
			PYTHON_LIST_TYPE.getFlavor(), CPP_BYTE_ARRAY_TYPE.getFlavor(),
			DataFlavor.stringFlavor };
		private final List<DataFlavor> flavorList = Arrays.asList(flavors);

		private final String byteString;

		private final String byteViewerRepresentation;

		public ByteViewerTransferable(String byteString) {
			this(byteString, null);
		}

		public ByteViewerTransferable(String byteString, String byteViewerRepresentation) {
			this.byteString = byteString;
			this.byteViewerRepresentation = byteViewerRepresentation;
		}

		@Override
		public Object getTransferData(DataFlavor flavor)
				throws UnsupportedFlavorException, IOException {
			if (flavor.equals(DataFlavor.stringFlavor)) {
				if (byteViewerRepresentation != null) {
					return byteViewerRepresentation;
				}
				return byteString; // just default to the byte string when no 'special' string data
			}
			if (flavor.equals(BYTE_STRING_TYPE.getFlavor())) {
				return byteString;
			}
			if (flavor.equals(BYTE_STRING_NO_SPACE_TYPE.getFlavor())) {
				return byteString;
			}
			if (flavor.equals(PYTHON_BYTE_STRING_TYPE.getFlavor())) {
				return byteString;
			}
			if (flavor.equals(PYTHON_LIST_TYPE.getFlavor())) {
				return byteString;
			}
			if (flavor.equals(CPP_BYTE_ARRAY_TYPE.getFlavor())) {
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
