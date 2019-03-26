/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.reader;

import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.List;

import org.catacombae.hfsexplorer.ObjectContainer;
import org.catacombae.hfsexplorer.types.hfscommon.CommonHFSCatalogFile;
import org.catacombae.hfsexplorer.types.hfsplus.HFSCatalogNodeID;
import org.catacombae.hfsexplorer.types.hfsplus.HFSPlusCatalogFile;
import org.catacombae.jparted.lib.fs.*;
import org.catacombae.jparted.lib.fs.FSAttributes.POSIXFileAttributes;
import org.catacombae.jparted.lib.fs.hfscommon.HFSCommonFSFile;

import mobiledevices.dmg.decmpfs.DecmpfsHeader;
import mobiledevices.dmg.hfsplus.AttributesFileParser;

/**
 * 
 * @see org.catacombae.hfsexplorer.gui.FSEntrySummaryPanel
 *
 */
class DmgInfoGenerator {
	private DmgFileReader fileSystem;
	private String filePath;
	private AttributesFileParser parser;
	private FSEntry entry;
	private DateFormat df = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM);

	DmgInfoGenerator(DmgFileReader fileSystem, String filePath, AttributesFileParser parser) {
		this.fileSystem = fileSystem;
		this.filePath = filePath;
		this.parser = parser;
		this.entry = fileSystem.getFileByPath(filePath);
	}

	List<String> getInformation() {
		List<String> infoList = new ArrayList<String>();

		if (entry == null) {
			infoList.add("<< no information available >>");
			return infoList;
		}

		infoList.add("Name: " + entry.getName());

		if (entry instanceof FSFile) {
			FSFile file = (FSFile) entry;
			infoList.add("Type: " + "File");
			infoList.add("Total Size: " + getSizeString(file.getCombinedLength()));
			FSFork[] allForks = file.getAllForks();
			for (FSFork fork : allForks) {
				infoList.add(
					"    " + fork.getForkIdentifier() + ": " + getSizeString(fork.getLength()));
			}
			appendFileID(infoList, file);

			if (parser != null) {
				try {
					DecmpfsHeader decmpfsHeader = parser.getDecmpfsHeader(file);
					if (decmpfsHeader != null) {
						infoList.add(
							"Decmpfs Size: " + getSizeString(decmpfsHeader.getUncompressedSize()));
					}
				}
				catch (IOException e) {
				}
			}
		}
		else if (entry instanceof FSFolder) {
			FSFolder folder = (FSFolder) entry;
			infoList.add("Type: " + "Folder");
			infoList.add("Size: " + startFolderSizeCalculation(folder));
		}
		else if (entry instanceof FSLink) {
			FSLink link = (FSLink) entry;

			FSEntry linkTarget =
				link.getLinkTarget(fileSystem.convertPathToArrayAndStripFileSystemName(filePath));
			if (linkTarget == null) {
				infoList.add("Type: " + "Symbolic link (broken)");
				infoList.add("Size: " + "- (broken link)");
			}
			else if (linkTarget instanceof FSFile) {
				FSFile file = (FSFile) linkTarget;
				infoList.add("Type: " + "Symbolic link (file)");
				infoList.add("Size: " + getSizeString(file.getMainFork().getLength()));
				FSFork[] allForks = file.getAllForks();
				for (FSFork fork : allForks) {
					infoList.add(
						"    " + fork.getForkIdentifier() + ": " + getSizeString(fork.getLength()));
				}
			}
			else if (linkTarget instanceof FSFolder) {
				FSFolder folder = (FSFolder) linkTarget;
				infoList.add("Type: " + "Symbolic link (folder)");
				infoList.add("Size: " + startFolderSizeCalculation(folder));
			}
			else {
				infoList.add("Type: " + "Symbolic link (unknown [" + linkTarget.getClass() + "])");
				infoList.add("Size: " + "- (unknown type)");
			}
			infoList.add("Link Target: " + link.getLinkTargetString());
		}
		else {
			infoList.add("Type: " + "Unknown [" + entry.getClass() + "]");
			infoList.add("Size: " + "- (unknown size)");
		}

		FSAttributes attrs = entry.getAttributes();

		appendDateInformation(attrs, infoList);
		appendPosixInformation(attrs, infoList);
		appendWindowsInformation(attrs, infoList);

		return infoList;
	}

	private void appendFileID(List<String> infoList, FSFile file) {
		try {
			HFSCommonFSFile hfsFile = (HFSCommonFSFile) file;
			CommonHFSCatalogFile catalogFile = hfsFile.getInternalCatalogFile();
			CommonHFSCatalogFile.HFSPlusImplementation hfsPlusCatalogFile =
				(CommonHFSCatalogFile.HFSPlusImplementation) catalogFile;
			HFSPlusCatalogFile underlying = hfsPlusCatalogFile.getUnderlying();
			HFSCatalogNodeID fileID = underlying.getFileID();
			infoList.add("File ID: 0x" + Integer.toHexString(fileID.toInt()));
		}
		catch (Exception e) {
			infoList.add("Unable to obtain file ID. " + e.getMessage());
		}
	}

	private void appendPosixInformation(FSAttributes attrs, List<String> infoList) {
		if (attrs.hasPOSIXFileAttributes()) {
			POSIXFileAttributes posixAttrs = attrs.getPOSIXFileAttributes();
			infoList.add("Permissions: " + posixAttrs.getPermissionString());
			infoList.add("User ID:     " + posixAttrs.getUserID());
			infoList.add("Group ID:    " + posixAttrs.getGroupID());
		}
	}

	private void appendWindowsInformation(FSAttributes attrs, List<String> infoList) {
		if (attrs.hasWindowsFileAttributes()) {
			WindowsFileAttributes windowsFileAttributes = attrs.getWindowsFileAttributes();
			infoList.add("Archive:    " + windowsFileAttributes.isArchive());
			infoList.add("Compressed: " + windowsFileAttributes.isCompressed());
			infoList.add("Directory:  " + windowsFileAttributes.isDirectory());
			infoList.add("Encrypted:  " + windowsFileAttributes.isEncrypted());
			infoList.add("Hidden:     " + windowsFileAttributes.isHidden());
			infoList.add("Normal:     " + windowsFileAttributes.isNormal());
			infoList.add("Off-line:   " + windowsFileAttributes.isOffline());
			infoList.add("Read-only:  " + windowsFileAttributes.isReadOnly());
			infoList.add("Reparse:    " + windowsFileAttributes.isReparsePoint());
			infoList.add("Sparse:     " + windowsFileAttributes.isSparseFile());
			infoList.add("System:     " + windowsFileAttributes.isSystem());
			infoList.add("Temp:       " + windowsFileAttributes.isTemporary());
			infoList.add("Virtual:    " + windowsFileAttributes.isVirtual());
		}
	}

	private void appendDateInformation(FSAttributes attributes, List<String> infoList) {
		if (attributes.hasCreateDate()) {
			infoList.add("Created: " + df.format(attributes.getCreateDate()));
		}
		if (attributes.hasModifyDate()) {
			infoList.add("Contents Modified: " + df.format(attributes.getModifyDate()));
		}
		if (attributes.hasAttributeModifyDate()) {
			infoList.add("Attributes Modified: " + df.format(attributes.getAttributeModifyDate()));
		}
		if (attributes.hasAccessDate()) {
			infoList.add("Last Accessed: " + df.format(attributes.getAccessDate()));
		}
		if (attributes.hasBackupDate()) {
			infoList.add("Last Backup: " + df.format(attributes.getBackupDate()));
		}
	}

	private String getSizeString(long result) {
		String baseString = Long.toString(result);
		return baseString + " bytes";
	}

	private String startFolderSizeCalculation(FSFolder folder) {
		String resultString;
		try {
			ObjectContainer<Long> result = new ObjectContainer<Long>((long) 0);
			calculateFolderSize(folder, result);
			resultString = getSizeString(result.o);
		}
		catch (Exception e) {
			e.printStackTrace();
			resultString = "Exception while calculating! See debug console for info...";
		}
		return resultString;
	}

	private void calculateFolderSize(FSFolder folder, ObjectContainer<Long> result) {
		for (FSEntry entry : folder.listEntries()) {
			if (entry instanceof FSFile) {
				Long value = result.o;
				value += ((FSFile) entry).getMainFork().getLength();
				result.o = value;
			}
			else if (entry instanceof FSFolder) {
				calculateFolderSize((FSFolder) entry, result);
			}
			else if (entry instanceof FSLink) {
				/* Do nothing. Symbolic link targets aren't part of the folder. */
			}
			else {
				System.err.println("FSEntrySummaryPanel.calculateFolderSize():" +
					" unexpected type " + entry.getClass());
			}
		}
	}

}
