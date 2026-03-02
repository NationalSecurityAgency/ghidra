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
package ghidra.file.formats.yaffs2;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.*;

import org.apache.commons.io.FilenameUtils;

import ghidra.app.util.bin.*;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.*;
import ghidra.program.model.lang.Endian;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * File system implementation for YAFFS2 images with 2048 byte pages and 64 bytes of OOB data
 * after each page.
 * <p>
 * The image file is made up of concatenated 2112 byte pages (2048 bytes data and 64 bytes OOB)
 * formatted such:
 * <p>
 * <pre>
 *  page { 
 * 	struct obj_hdr { [512 bytes] ... parentObjId, name, size, datetime, etc ... } 
 * 	...1536 bytes... 
 * 	struct oob { [64 bytes] objId, misc etc }
 * } (repeated)
 * </pre>
 * <p>
 * If page was a File obj_hdr, the pages following will be the data of that file:
 * <p>
 * <pre>
 * page { 
 * 	2048 bytes filedata
 * 	struct oob { [64 bytes] .... }
 * }
 * </pre>
 * <p>
 * NOTES:
 * <ul>
 * 	<li>There is no header / superblock at the beginning of the filesystem data, so parameters
 * 	(like the page size or OOB data size, endianness, etc) are not discoverable without some
 * 	guessing / try-and-see-if-it-produces-valid-looking-data.
 * 	<li>Changing the size of the page changes the default size of the OOB data, which can change the
 * 	layout of the OOB data.
 * 	<li>The OOB data might be written in YAFFS-original format, or might be written in more recent
 * 	Linux MTD format.  (see mkyaff's --yaffs-ecclayout startup option).  This impl only handles
 * 	YAFFS-original format.
 * 	<li>This impl has only been tested with images that are freshly created with no 
 * 	usage / modifications.
 * </ul>   
 */
@FileSystemInfo(type = "yaffs2", description = "YAFFS2", factory = YAFFS2FileSystemFactory.class)
public class YAFFS2FileSystem extends AbstractFileSystem<YAFFS2FileSystem.Metadata> {
	static class Metadata {
		final long objId;
		int pageNum;
		int equivPageNum; // if hardlink

		Metadata(long objId) {
			this.objId = objId;
		}
	}

	private ByteProvider provider;
	private int oobSize;
	private int pageSize;
	private int stride;
	private Endian endian;

	public YAFFS2FileSystem(ByteProvider provider, int pageSize, int oobSize, Endian endian,
			FSRLRoot fsFSRL, FileSystemService fsService) {
		super(fsFSRL, fsService);

		this.pageSize = pageSize;
		this.oobSize = oobSize;
		this.stride = pageSize + oobSize;
		this.endian = endian;
		this.provider = provider;
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			FSUtilities.uncheckedClose(provider, null);
			provider = null;
		}
		fsIndex.clear();
	}

	public void mount(TaskMonitor monitor) throws IOException, CancelledException {
		int pageCount = (int) (provider.length() / stride);
		if (provider.length() % stride != 0) {
			Msg.warn(this, "Non-integral yaffs2 file system image file length: %d, %d, %d"
					.formatted(provider.length(), pageSize, oobSize));
		}

		// accumulate objId -> metadata(pagenum) mappings, allowing an earlier version of an object
		// to be overwritten by a 'newer' definition in a later page.
		Map<Long, Metadata> objIdToMetadata = new HashMap<>();
		for (int pageNum = 0; pageNum < pageCount; pageNum++) {
			monitor.checkCancelled();
			HeaderWithOOB page = readPage(pageNum);
			if (page == null) {
				break;
			}
			if (!page.hdr.isValid(provider)) {
				break;
			}
			Metadata metadata =
				objIdToMetadata.computeIfAbsent(page.oob.getObjectId(), Metadata::new);
			metadata.pageNum = pageNum;
			pageNum += page.hdr.getDataPageCount(pageSize);
		}

		objIdToMetadata.entrySet()
				.stream()
				.sorted((o1, o2) -> Long.compare(o1.getKey(), o2.getKey()))
				.forEach(entry -> {
					try {
						long objId = entry.getKey();
						Metadata metadata = entry.getValue();
						HeaderWithOOB page = readPage(metadata.pageNum);
						if (metadata.pageNum == 0 && objId == 1 &&
							page.hdr.getParentObjectId() == 1) {
							// skip entry that is just the 'root' directory
							return;
						}

						long parentObjId = page.hdr.getParentObjectId();
						GFile parent = parentObjId == 1
								? fsIndex.getRootDir()
								: fsIndex.getFileByIndex(parentObjId);
						if (parent == null) {
							parent = fsIndex.getRootDir();
							Msg.warn(this,
								"Unable to find parent %x of %x".formatted(parentObjId, objId));
						}
						String name = page.hdr.getName();
						switch (page.hdr.getObjectTypeEnum()) {
							case File:
								fsIndex.storeFileWithParent(name, parent, objId, false,
									page.hdr.calcFileSize(), metadata);
								break;
							case Directory:
								fsIndex.storeFileWithParent(name, parent, objId, true, -1,
									metadata);
								break;
							case Symlink:
								fsIndex.storeSymlinkWithParent(name, parent, objId,
									page.hdr.getAliasFileName(), 0, metadata);
								break;
							case Hardlink:
								Metadata equivTarget = objIdToMetadata.get(page.hdr.getEquivId());
								if (equivTarget == null) {
									Msg.warn(this,
										"Unable to find hardlink equiv: %x, %x, skipping: %s"
												.formatted(metadata.pageNum, page.hdr.getEquivId(),
													name));
									break;
								}

								metadata.equivPageNum = equivTarget.pageNum;
								HeaderWithOOB equivTargetObj = readPage(metadata.equivPageNum);
								fsIndex.storeFileWithParent(name, parent, objId, false,
									equivTargetObj.hdr.calcFileSize(), metadata);
								break;
							default:
								break;
						}
					}
					catch (IOException e) {
						// shouldn't happen
					}
				});
	}

	private record HeaderWithOOB(YAFFS2Header hdr, YAFFS2OOBStruct oob) {}

	private HeaderWithOOB readPage(int pageNum) throws IOException {
		byte[] pageBytes = provider.readBytes(pageToOffset(pageNum), stride);
		if (isDefaultPage(pageBytes)) {
			return null;
		}
		BinaryReader br =
			new BinaryReader(new ByteArrayProvider(pageBytes), endian == Endian.LITTLE);
		YAFFS2Header hdr = YAFFS2Header.read(br);
		br.setPointerIndex(pageSize);
		YAFFS2OOBStruct tag = YAFFS2OOBStruct.read(br, oobSize);
		return new HeaderWithOOB(hdr, tag);
	}

	private boolean isDefaultPage(byte[] pageBytes) {
		// return true if page is entirely 00's or FF's
		byte b = pageBytes[0];
		if (b != 0 && b != -1) {
			return false;
		}
		for (int i = 0; i < pageBytes.length; i++) {
			if (pageBytes[i] != b) {
				return false;
			}
		}
		return true;
	}

	private long pageToOffset(int pageNum) {
		return pageNum * stride;
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		GFile resolvedFile = fsIndex.resolveSymlinks(file);
		Metadata metadata = fsIndex.getMetadata(resolvedFile);
		if (metadata == null) {
			return null;
		}
		int pageNum = metadata.pageNum;
		HeaderWithOOB page = readPage(pageNum);
		if (page.hdr.getObjectTypeEnum() == YAFFS2ObjectType.Hardlink) {
			pageNum = metadata.equivPageNum;
			page = readPage(pageNum);
		}

		RangeMappedByteProvider result =
			new RangeMappedByteProvider(provider, resolvedFile.getFSRL());
		long byteCount = page.hdr.calcFileSize();
		pageNum++;
		for (long offset = pageToOffset(pageNum); byteCount > 0; pageNum++) {
			int bytesInPage = (int) Math.min(byteCount, pageSize);
			result.addRange(offset, bytesInPage);
			byteCount -= bytesInPage;
		}

		return result;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		if (fsIndex.getRootDir().equals(file)) {
			return FileAttributes.of( // file, attrs
				FileAttribute.create("Page Size", pageSize),
				FileAttribute.create("OOB Size", oobSize));
		}
		Metadata metadata = fsIndex.getMetadata(file);
		if (metadata != null) {
			try {
				HeaderWithOOB origpage = readPage(metadata.pageNum);
				HeaderWithOOB page = origpage.hdr.getObjectTypeEnum() == YAFFS2ObjectType.Hardlink
						? readPage(metadata.equivPageNum)
						: origpage;
				YAFFS2ObjectType objType = page.hdr.getObjectTypeEnum();

				return FileAttributes.of( // file attrs
					FileAttribute.create(NAME_ATTR, origpage.hdr.getName()),
					FileAttribute.create(PATH_ATTR,
						FilenameUtils.getFullPathNoEndSeparator(file.getPath())),
					objType == YAFFS2ObjectType.File
							? FileAttribute.create(SIZE_ATTR, page.hdr.calcFileSize())
							: null,
					FileAttribute.create(MODIFIED_DATE_ATTR,
						new Date(page.hdr.getYstMTime() * 1000)),
					FileAttribute.create(CREATE_DATE_ATTR, new Date(page.hdr.getYstCTime() * 1000)),
					FileAttribute.create(ACCESSED_DATE_ATTR,
						new Date(page.hdr.getYstATime() * 1000)),
					FileAttribute.create(FILE_TYPE_ATTR, convertFileType(objType)),
					FileAttribute.create(USER_ID_ATTR, page.hdr.getYstUId()),
					FileAttribute.create(GROUP_ID_ATTR, page.hdr.getYstGId()),
					FileAttribute.create(UNIX_ACL_ATTR, page.hdr.getYstMode()),
					origpage.hdr.getObjectTypeEnum() == YAFFS2ObjectType.Symlink
							? FileAttribute.create(SYMLINK_DEST_ATTR,
								origpage.hdr.getAliasFileName())
							: null,
					FileAttribute.create("Object Id", "%08x".formatted(origpage.oob.getObjectId())),
					FileAttribute.create("Parent Id",
						"%08x".formatted(origpage.hdr.getParentObjectId())),
					FileAttribute.create("Page Number", "%08x".formatted(metadata.pageNum)));
			}
			catch (IOException e) {
				// fall thru
			}
		}
		return null;
	}

	private FileType convertFileType(YAFFS2ObjectType objType) {
		return switch (objType) {
			case File -> FileType.FILE;
			case Directory -> FileType.DIRECTORY;
			case Hardlink -> FileType.FILE;
			case Symlink -> FileType.SYMBOLIC_LINK;
			default -> FileType.OTHER;
		};
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

}
