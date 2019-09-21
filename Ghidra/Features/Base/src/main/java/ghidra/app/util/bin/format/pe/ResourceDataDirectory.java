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
package ghidra.app.util.bin.format.pe;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.bin.format.FactoryBundledWithBinaryReader;
import ghidra.app.util.bin.format.pe.resource.*;
import ghidra.app.util.datatype.microsoft.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Points to the root resource directory.
 */
public class ResourceDataDirectory extends DataDirectory {
	private final static String NAME = "IMAGE_DIRECTORY_ENTRY_RESOURCE";
	/**
	 * The size of a resource directory entry, in bytes.
	 */
	public final static int IMAGE_SIZEOF_RESOURCE_DIRECTORY_ENTRY = 8;
	/**
	 * The size of a resource directory, in bytes.
	 */
	public final static int IMAGE_SIZEOF_RESOURCE_DIRECTORY = 16;
	/**
	 * A flag indicating that a resources is a string.
	 */
	public final static int IMAGE_RESOURCE_NAME_IS_STRING = 0x80000000;
	/**
	 * A flag indicating that a resources is a directory.
	 */
	public final static int IMAGE_RESOURCE_DATA_IS_DIRECTORY = 0x80000000;
	/**
	 * A lookup table to obtain a string name for a resource type.
	 */
	public final static String[] PREDEFINED_RESOURCE_NAMES = { "0", "Cursor", "Bitmap", "Icon",
		"Menu", "Dialog", "StringTable", "FontDir", "Font", "Accelerator", "RC_Data",
		"MessageTable", "GroupCursor", "13", "GroupIcon", "15", "Version", "DialogInclude", "18",
		"PlugAndPlay", "VXD", "ANI_Cursor", "ANI_Icon", "HTML", "Manifest" };

	/**
	 * Not defined in documentation but PNGs and WAVs are both this type
	 */
	public final static byte RT_NOTDEFINED = 0;
	/**
	/**
	 * Hardware-dependent cursor resource.
	 */
	public final static byte RT_CURSOR = 1;
	/**
	 * Bitmap resource.
	 */
	public final static byte RT_BITMAP = 2;
	/**
	 * Hardware-dependent icon resource.
	 */
	public final static byte RT_ICON = 3;
	/**
	 * Menu resource.
	 */
	public final static byte RT_MENU = 4;
	/**
	 * Dialog box.
	 */
	public final static byte RT_DIALOG = 5;
	/**
	 * String-table entry.
	 */
	public final static byte RT_STRING = 6;
	/**
	 * Font directory resource.
	 */
	public final static byte RT_FONTDIR = 7;
	/**
	 * Font resource.
	 */
	public final static byte RT_FONT = 8;
	/**
	 * Accelerator table.
	 */
	public final static byte RT_ACCELERATOR = 9;
	/**
	 * Application-defined resource (raw data).
	 */
	public final static byte RT_RCDATA = 10;
	/**
	 * Message-table entry.
	 */
	public final static byte RT_MESSAGETABLE = 11;
	/**
	 * Hardware-independent cursor resource.
	 */
	public final static byte RT_GROUP_CURSOR = 12;
	// 13 is not defined...
	/**
	 * Hardware-independent icon resource.
	 */
	public final static byte RT_GROUP_ICON = 14;
	// 15 is not defined...
	/**
	 * Version resource.
	 */
	public final static byte RT_VERSION = 16;

	public final static byte RT_DLGINCLUDE = 17;
	// 18 is not defined...
	/**
	 * Plug and Play resource.
	 */
	public final static byte RT_PLUGPLAY = 19;
	/**
	 * VXD resource.
	 */
	public final static byte RT_VXD = 20;
	/**
	 * Animated cursor resource.
	 */
	public final static byte RT_ANICURSOR = 21;
	/**
	 * Animated icon resource.
	 */
	public final static byte RT_ANIICON = 22;
	/**
	 * HTML resource.
	 */
	public final static byte RT_HTML = 23;
	/**
	 * Manifest resource
	 */
	public final static byte RT_MANIFEST = 24;

	private ResourceDirectory rootDirectory;

	public static Set<Integer> directoryMap;

	static ResourceDataDirectory createResourceDataDirectory(NTHeader ntHeader,
			FactoryBundledWithBinaryReader reader) throws IOException {
		ResourceDataDirectory resourceDataDirectory =
			(ResourceDataDirectory) reader.getFactory().create(ResourceDataDirectory.class);
		resourceDataDirectory.initResourceDataDirectory(ntHeader, reader);
		return resourceDataDirectory;
	}

	/**
	 * DO NOT USE THIS CONSTRUCTOR, USE create*(GenericFactory ...) FACTORY METHODS INSTEAD.
	 */
	public ResourceDataDirectory() {
	}

	private void initResourceDataDirectory(NTHeader ntHeader, FactoryBundledWithBinaryReader reader)
			throws IOException {
		directoryMap = new HashSet<>();
		processDataDirectory(ntHeader, reader);
	}

	public ResourceDirectory getRootDirectory() {
		return rootDirectory;
	}

	@Override
	public String getDirectoryName() {
		return NAME;
	}

	@Override
	public void markup(Program program, boolean isBinary, TaskMonitor monitor, MessageLog log,
			NTHeader ntHeader) throws DuplicateNameException, CodeUnitInsertionException,
			DataTypeConflictException, IOException {

		if (rootDirectory == null) {
			return;
		}
		monitor.setMessage("[" + program.getName() + "]: resources...");
		Address addr = PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		if (!program.getMemory().contains(addr)) {
			return;
		}
		createDirectoryBookmark(program, addr);

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();

		HashMap<Integer, Integer> countMap = new HashMap<>();

		List<ResourceInfo> resources = getResources();
		if (resources == null) {
			return;
		}

		try {
			for (ResourceInfo info : resources) {
				if (monitor.isCancelled()) {
					return;
				}

				Integer cnt = countMap.get(info.getTypeID());
				if (cnt == null) {
					countMap.put(info.getTypeID(), 1);
				}
				else {
					countMap.put(info.getTypeID(), cnt + 1);
				}

				addr = space.getAddress(va(info.getAddress(), isBinary));

				try {
					program.getSymbolTable().createLabel(addr, info.getName(), SourceType.IMPORTED);
				}
				catch (InvalidInputException e) {
					Msg.error(this, "Invalid Input Exception: " + e.getMessage(), e);
				}

				String cmt =
					"Size of resource: 0x" + Integer.toHexString(info.getSize()) + " bytes";
				StringBuilder extraComment = new StringBuilder();

				if (info.getTypeID() == ResourceDataDirectory.RT_NOTDEFINED) {
					if (info.getName().startsWith("Rsrc_IMAGE") ||
						info.getName().startsWith("Rsrc_PNG")) {
						DataType dataType = null;
						try {
							// Check for PNG magic number
							if (program.getMemory().getInt(addr) == 0x474e5089) {
								dataType = new PngDataType();
							}
							// Check for GIF magic number
							else if (program.getMemory().getInt(addr) == 0x47494638) {
								dataType = new GifDataType();
							}

						}
						catch (MemoryAccessException e) {
							// ignore - let createData produce error
						}
						PeUtils.createData(program, addr, dataType, log);
					}
					else if (info.getName().startsWith("Rsrc_WAV")) {
						DataType dataType = null;
						// Check for WAV magic number
						try {
							if (program.getMemory().getInt(addr) == 0x46464952) {
								dataType = new WAVEDataType();
							}
						}
						catch (MemoryAccessException e) {
							// ignore - let createData produce error
						}
						PeUtils.createData(program, addr, dataType, log);
					}
					else if (info.getName().startsWith("Rsrc_WEVT")) {
						DataType dataType = null;
						// Check for WEVT magic number "CRIM"
						try {
							if (program.getMemory().getInt(addr) == 0x4d495243) {
								dataType = new WEVTResourceDataType();
							}
						}
						catch (MemoryAccessException e) {
							// ignore - let createData produce error
						}
						PeUtils.createData(program, addr, dataType, log);
					}
					else if (info.getName().startsWith("Rsrc_MUI")) {
						DataType dataType = null;
						// Check for MUI magic number
						try {
							if (program.getMemory().getInt(addr) == 0xfecdfecd) {
								dataType = new MUIResourceDataType();
							}
						}
						catch (MemoryAccessException e) {
							// ignore - let createData produce error
						}
						PeUtils.createData(program, addr, dataType, log);
					}
					else {
						//add byte array of correct size until data type can be created for missing types- this will keep auto analysis from incorrectly analyzing here
						ArrayDataType byteArray =
							new ArrayDataType(ByteDataType.dataType, info.getSize(), 1);
						PeUtils.createData(program, addr, byteArray, log);
					}
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_STRING) {
					for (int s = 0; s < 0x10; ++s) {
						int id = ((info.getID() - 1) * 0x10) + s;
						setEolComment(program, addr, "Rsrc String ID " + id);
						PascalUnicodeDataType str = new PascalUnicodeDataType();
						PeUtils.createData(program, addr, str, log);
						Data data = program.getListing().getDataAt(addr);
						if (data != null) {
							addr = data.getMaxAddress().add(1);
						}
					}
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_BITMAP) {
					BitmapResourceDataType bitmapDatatype = new BitmapResourceDataType();
					PeUtils.createData(program, addr, bitmapDatatype, log);
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_ICON) {
					DataType iconDataType = null;
					try {
						// Check for PNG magic number
						if (program.getMemory().getInt(addr) == 0x474e5089) {
							iconDataType = new PngDataType();
						}
						// Check for GIF magic number
						else if (program.getMemory().getInt(addr) == 0x47494638) {
							iconDataType = new GifDataType();
						}
					}
					catch (MemoryAccessException e) {
						// ignore - let createData produce error
					}
					if (iconDataType == null) {
						// assume Icon resource by default if not PNG
						iconDataType = new IconResourceDataType();
					}
					PeUtils.createData(program, addr, iconDataType, log);
				}
				//			else if (info.getTypeID() == ResourceDataDirectory.RT_CURSOR) {
				//
				//			}
				else if (info.getTypeID() == ResourceDataDirectory.RT_GROUP_ICON) {
					GroupIconResourceDataType groupIconDataType = new GroupIconResourceDataType();
					PeUtils.createData(program, addr, groupIconDataType, log);
				}
				//else if (info.getTypeID() == ResourceDataDirectory.RT_GROUP_CURSOR) {
				//
				//			}
				else if (info.getTypeID() == ResourceDataDirectory.RT_MENU) {
					MenuResourceDataType menuResourceDataType = new MenuResourceDataType();
					Data createData = PeUtils.createData(program, addr, menuResourceDataType, log);
					if (createData != null) {
						extraComment.append("\n" + setExtraCommentForMenuResource(createData));
					}
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_DIALOG) {
					DialogResourceDataType dialogResourceDataType = new DialogResourceDataType();
					Data createData =
						PeUtils.createData(program, addr, dialogResourceDataType, log);
					if (createData != null) {
						extraComment.append("\n" + setExtraCommentForDialogResource(createData));
					}
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_VERSION) {
					processVersionInfo(addr, info, program, log, monitor);
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_MANIFEST) { // XML manifest string
					PeUtils.createData(program, addr, TerminatedStringDataType.dataType, log);
				}
				else if (info.getTypeID() == ResourceDataDirectory.RT_HTML) {
					HTMLResourceDataType htmlResourceDataType = new HTMLResourceDataType();
					PeUtils.createData(program, addr, htmlResourceDataType, info.getSize(), log);
				}
				else {
					//add byte array of correct size until data type can be created for missing types- this will keep auto analysis from incorrectly analyzing here
					ArrayDataType byteArray =
						new ArrayDataType(ByteDataType.dataType, info.getSize(), 1);
					PeUtils.createData(program, addr, byteArray, log);
				}

				setPlateComment(program, addr, info.getName() + " " + cmt + extraComment);
			}

		}
		catch (Exception e) {
			Msg.error(this, "Invalid resource data: " + e.getMessage(), e);
		}

		Address resourceBase =
			PeUtils.getMarkupAddress(program, isBinary, ntHeader, virtualAddress);
		markupDirectory(rootDirectory, resourceBase, resourceBase, program, isBinary, monitor, log);
	}

	private void processVersionInfo(Address addr, ResourceInfo info, Program program,
			MessageLog log, TaskMonitor monitor) throws IOException {
		Options infoList = program.getOptions(Program.PROGRAM_INFO);
		VS_VERSION_INFO versionInfo = null;
		try {
			int ptr = ntHeader.rvaToPointer(info.getAddress());
			if (ptr < 0) {
				Msg.error(this, "Invalid RVA " + Integer.toHexString(info.getAddress()));
				return;
			}
			versionInfo = new VS_VERSION_INFO(reader, ptr);
			PeUtils.createData(program, addr, versionInfo.toDataType(), log);
		}
		catch (DuplicateNameException e) {
			Msg.error(this, "Unexpected Exception: VS_VERSION_INFO structure previously defined",
				e);
		}
		VS_VERSION_CHILD[] children = versionInfo.getChildren();
		for (VS_VERSION_CHILD child : children) {
			if (monitor.isCancelled()) {
				return;
			}
			markupChild(child, addr, program, log, monitor);
		}

		String[] keys = versionInfo.getKeys();
		for (String key : keys) {
			if (monitor.isCancelled()) {
				return;
			}
			String value = versionInfo.getValue(key);
			infoList.setString(key, value);
		}
	}

	private void markupChild(VS_VERSION_CHILD child, Address parentAddr, Program program,
			MessageLog log, TaskMonitor monitor) {
		Address childAddr = parentAddr.add(child.getRelativeOffset());
		try {
			DataType infoType = child.toDataType();
			if (infoType == null) {
				return;
			}
			PeUtils.createData(program, childAddr, infoType, log);

			// child name string
			PeUtils.createData(program, childAddr.add(child.getNameRelativeOffset()),
				TerminatedUnicodeDataType.dataType, log);

			if (child.valueIsUnicodeString()) {
				// unicode value
				PeUtils.createData(program, childAddr.add(child.getValueRelativeOffset()),
					TerminatedUnicodeDataType.dataType, log);
			}
			else if (child.valueIsDWord()) {
				// dword value
				PeUtils.createData(program, childAddr.add(child.getValueRelativeOffset()),
					DWordDataType.dataType, log);
			}
			else if (child.hasChildren()) {
				// markup nested children
				VS_VERSION_CHILD[] children = child.getChildren();
				for (VS_VERSION_CHILD element : children) {
					if (monitor.isCancelled()) {
						return;
					}
					markupChild(element, childAddr, program, log, monitor);
				}
			}
		}
		catch (DuplicateNameException e) {
			Msg.error(this,
				"Unexpected Exception: " + child.getChildName() + " structure previously defined",
				e);
		}
	}

	private void markupDirectory(ResourceDirectory directory, Address directoryAddr,
			Address resourceBase, Program program, boolean isBinary, TaskMonitor monitor,
			MessageLog log) throws IOException, DuplicateNameException, CodeUnitInsertionException {

		PeUtils.createData(program, directoryAddr, directory.toDataType(), log);
		directoryAddr = directoryAddr.add(ResourceDirectory.SIZEOF);

		List<ResourceDirectoryEntry> entries = directory.getEntries();
		for (ResourceDirectoryEntry entry : entries) {
			if (monitor.isCancelled()) {
				return;
			}

			PeUtils.createData(program, directoryAddr, entry.toDataType(), log);
			directoryAddr = directoryAddr.add(ResourceDirectoryEntry.SIZEOF);

			ResourceDirectory subDirectory = entry.getSubDirectory();
			if (subDirectory != null) {
				Address subDirectoryAddr = resourceBase.add(entry.getOffsetToDirectory());
				markupDirectory(subDirectory, subDirectoryAddr, resourceBase, program, isBinary,
					monitor, log);
			}

			ResourceDataEntry data = entry.getData();
			if (data != null) {
				Address dataAddr = resourceBase.add(entry.getOffsetToData());
				PeUtils.createData(program, dataAddr, data.toDataType(), log);
			}

			ResourceDirectoryStringU string = entry.getDirectoryString();
			if (string != null && string.getLength() > 0) {
				Address strAddr = resourceBase.add(entry.getNameOffset() & 0x7fffffff);
				PeUtils.createData(program, strAddr, string.toDataType(), log);
			}
		}
	}

	@Override
	public boolean parse() throws IOException {
		int ptr = getPointer();
		if (ptr < 0) {
			return false;
		}
		int resourceBase = ptr;

		rootDirectory = new ResourceDirectory(reader, ptr, resourceBase, true, ntHeader);
		return true;
	}

	//parse Dialog data type to pull out nice header comment
	private String setExtraCommentForDialogResource(Data data) throws MemoryAccessException {

		final String[] afterTemplate = { "Menu", "Class", "Title", "Font Size", "Font Name" };
		final String[] templateType0 = { "None", "Predefined", "None" };
		final String[] afterItem = { "Class", "Title", "Data" };

		//just need this to use a method from the class
		DialogResourceDataType temp = new DialogResourceDataType();

		DumbMemBufferImpl buffer = new DumbMemBufferImpl(data.getMemory(), data.getAddress());

		StringBuilder comment = new StringBuilder();
		if (data.getBaseDataType().getName().equals("DialogResource")) {

			int offset = 0;
			//get first structure
			Data componentAt = data.getComponentAt(offset);
			if (componentAt.isStructure() &&
				componentAt.getBaseDataType().getName().equals("DLGTEMPLATE")) {

				//determine if 3 or 5 components after initial structure
				int numAfter = 3;
				if ((buffer.getByte(0) & 0x40) > 0) {
					numAfter += 2;
				}

				int numItems = buffer.getShort(offset + 8);
				int currentItem = 0;
				comment.append("\nNumber of Items in Dialog: " + numItems);

				//get three or five components after initial structure
				for (int i = 0; i < numAfter; i++) {
					offset += componentAt.getLength();
					componentAt = data.getComponentAt(offset);
					comment.append("\n" + afterTemplate[i] + ": ");
					if (componentAt.getBaseDataType().getName().equals("short")) {
						comment.append(componentAt.getDefaultValueRepresentation());
					}
					if (componentAt.getBaseDataType().getName().equals("short[1]")) {
						if (buffer.getShort(offset) == 0x0000) {
							comment.append(templateType0[i]);
						}
					}
					if (componentAt.getBaseDataType().getName().equals("short[2]")) {
						if ((buffer.getShort(offset) & 0xffff) == 0xffff) {
							int ordinal = buffer.getShort(offset + 2);
							comment.append("External Ordinal Number " + ordinal);
						}
					}

					if (componentAt.getBaseDataType().getName().equals("unicode")) {
						comment.append(
							fixupStringRepForDisplay(componentAt.getDefaultValueRepresentation()));
					}
				}
				//loop over item structures
				comment.append("\n");
				while (currentItem < numItems) {
					offset += componentAt.getLength();
					componentAt = data.getComponentAt(offset);
					if (componentAt.getBaseDataType().getName().equals("DLGITEMTEMPLATE")) {
						currentItem++;
						comment.append("\nItem " + currentItem + ": ");
						//loop over three items after each item structure
						for (int i = 0; i < 3; i++) {
							offset += componentAt.getLength();
							componentAt = data.getComponentAt(offset);
							comment.append("\n   " + afterItem[i] + ": ");
							if (componentAt.getBaseDataType().getName().startsWith("short[")) {
								//no other info
								if (buffer.getShort(offset) == 0x0000) {
									comment.append("None");
								}
								//followed by ordinal
								else if ((buffer.getShort(offset) & 0xffff) == 0xffff) {
									int ordinal = buffer.getShort(offset + 2);
									comment.append(temp.getItemType(ordinal));
								}
								//first item is size array
								else {
									int sizeArray = buffer.getShort(offset);
									comment.append(
										"Size " + sizeArray + " (see internals of structure)");
								}
							}

							if (componentAt.getBaseDataType().getName().equals("unicode")) {
								comment.append(fixupStringRepForDisplay(
									componentAt.getDefaultValueRepresentation()));
							}
						}
					}

				}
			}

		}
		return comment.toString();

	}

	private String fixupStringRepForDisplay(String s) {
		// fixup the formatted string before embedding in PE loader artifacts
		// typically var s will look like u"blahblah".  Result will be "blahblah".
		return s.startsWith("u\"") || s.startsWith("U\"") ? s.substring(1 /* skip the leading 'u'*/)
				: s;
	}

	//parse Dialog data type to pull out nice header comment
	private String setExtraCommentForMenuResource(Data data) throws MemoryAccessException {

		short MF_POPUP = 0x0010;
		short LAST = 0x0090;

		DumbMemBufferImpl buffer = new DumbMemBufferImpl(data.getMemory(), data.getAddress());

		StringBuilder comment = new StringBuilder();
		if (data.getBaseDataType().getName().equals("MenuResource")) {

			//get first structure

			int numComponents = data.getNumComponents();
			boolean topLevel = false;
			for (int i = 0; i < numComponents; i++) {
				DataType dt = data.getComponent(i).getBaseDataType();
				int offset = data.getComponent(i).getRootOffset();

				if (dt.getName().equals("MENUITEM_TEMPLATE_HEADER")) {

					int version = buffer.getShort(offset);
					if (version != 0x0000) {
						return null;
					}

					int menuItemOffset = buffer.getShort(offset + 2);
					if (menuItemOffset < 0) {
						return null;
					}

				}
				if (dt.getName().equals("word")) {
					short option = buffer.getShort(offset);

					if (option == MF_POPUP) {
						topLevel = true; //this type has no mtID to skip
					}
					else if (option == LAST) {
						topLevel = true;
						i++; //skip the mtID
					}
					else {
						topLevel = false;
						i++; //skip the mtID
					}
				}
				if (dt.getName().equals("unicode")) {
					if (topLevel) {
						comment.append("\n");
					}
					else {
						comment.append("  ");
					}

					String menuString = fixupStringRepForDisplay(
						data.getComponentAt(offset).getDefaultValueRepresentation());
					menuString = menuString.replaceAll("\"", "");
					if (menuString.equals("")) {
						comment.append("-------------------\n");
					}
					else {
						comment.append(menuString + "\n");
					}
				}

			}

		}
		return comment.toString();

	}

	public List<ResourceInfo> getResources() {
		ArrayList<ResourceInfo> resources = new ArrayList<>();

		List<ResourceDirectoryEntry> entries = rootDirectory.getEntries();
		for (ResourceDirectoryEntry entry : entries) {
			List<ResourceInfo> entryResources = entry.getResources(0);
			for (ResourceInfo info : entryResources) {
				info.setName("Rsrc_" + info.getName());
				resources.add(info);
			}
		}

		Collections.sort(resources);

		return resources;
	}

	@Override
	public String toString() {
		StringBuffer buff = new StringBuffer();
		if (hasParsed) {
			buff.append("\t\t" + "Resource Directory: [" + super.toString() + "]" + "\n");
			List<ResourceInfo> resources = getResources();
			for (ResourceInfo info : resources) {
				buff.append(
					"\t\t\t" + "0x" + Long.toHexString(info.getAddress()) + "  " + info.getName() +
						"  Size: 0x" + Integer.toHexString(info.getSize()) + " bytes" + "\n");
			}
		}
		return buff.toString();
	}

	/**
	 * @see ghidra.app.util.bin.StructConverter#toDataType()
	 */
	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		return rootDirectory.toDataType();
	}
}
