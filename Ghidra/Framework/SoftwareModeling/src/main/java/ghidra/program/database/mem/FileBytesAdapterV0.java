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
package ghidra.program.database.mem;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import db.*;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.exception.VersionException;

/**
 * Initial version of the FileBytesAdapter
 */
class FileBytesAdapterV0 extends FileBytesAdapter {
	static final String TABLE_NAME = "File Bytes";
	static final int VERSION = 0;

	public static final int V0_FILENAME_COL = 0;
	public static final int V0_OFFSET_COL = 1;
	public static final int V0_SIZE_COL = 2;
	public static final int V0_BUF_IDS_COL = 3;
	public static final int V0_LAYERED_BUF_IDS_COL = 4;

	static final Schema SCHEMA = new Schema(VERSION, "Key",
		new Field[] { StringField.INSTANCE, LongField.INSTANCE, LongField.INSTANCE,
			BinaryField.INSTANCE, BinaryField.INSTANCE },
		new String[] { "Filename", "Offset", "Size", "Chain Buffer IDs",
			"Layered Chain Buffer IDs" });

	private Table table;
	private List<FileBytes> fileBytesList = new ArrayList<>();

	FileBytesAdapterV0(DBHandle handle, boolean create) throws VersionException, IOException {
		super(handle);

		if (create) {
			table = handle.createTable(TABLE_NAME, SCHEMA);
		}
		else {
			table = handle.getTable(TABLE_NAME);
			if (table == null) {
				throw new VersionException(true);
			}
			if (table.getSchema().getVersion() != VERSION) {
				throw new VersionException(VersionException.NEWER_VERSION, false);
			}
		}

		// load existing file bytes
		RecordIterator iterator = table.iterator();
		while (iterator.hasNext()) {
			DBRecord record = iterator.next();
			fileBytesList.add(new FileBytes(this, record));
		}

	}

	@Override
	FileBytes createFileBytes(String filename, long offset, long size, InputStream is)
			throws IOException {
		DBBuffer[] buffers = createBuffers(size, is);
		DBBuffer[] layeredBuffers = createLayeredBuffers(buffers);
		int[] bufIds = getIds(buffers);
		int[] layeredBufIds = getIds(layeredBuffers);
		DBRecord record = SCHEMA.createRecord(table.getKey());
		record.setString(V0_FILENAME_COL, filename);
		record.setLongValue(V0_OFFSET_COL, offset);
		record.setLongValue(V0_SIZE_COL, size);
		record.setField(V0_BUF_IDS_COL, new BinaryCodedField(bufIds));
		record.setField(V0_LAYERED_BUF_IDS_COL, new BinaryCodedField(layeredBufIds));
		table.putRecord(record);
		FileBytes fileBytes = new FileBytes(this, record);
		fileBytesList.add(fileBytes);
		return fileBytes;
	}

	@Override
	List<FileBytes> getAllFileBytes() {
		return fileBytesList;
	}

	@Override
	void refresh() throws IOException {
		Map<Long, FileBytes> map = new HashMap<>();
		List<FileBytes> newList = new ArrayList<>();

		for (FileBytes fileBytes : fileBytesList) {
			map.put(fileBytes.getId(), fileBytes);
		}

		RecordIterator iterator = table.iterator();
		while (iterator.hasNext()) {
			DBRecord record = iterator.next();
			FileBytes fileBytes = map.remove(record.getKey());
			if (fileBytes != null) {
				if (!fileBytes.refresh(record)) {
					// FileBytes attributes changed
					fileBytes.invalidate();
					fileBytes = null;
				}
			}
			if (fileBytes == null) {
				fileBytes = new FileBytes(this, record);
			}
			newList.add(fileBytes);
		}

		for (FileBytes fileBytes : map.values()) {
			fileBytes.invalidate();
		}
		fileBytesList = newList;
	}

	@Override
	boolean deleteFileBytes(FileBytes fileBytes) throws IOException {
		if (fileBytesList.remove(fileBytes)) {
			table.deleteRecord(fileBytes.getId());
			fileBytes.invalidate();
			return true;
		}
		return false;
	}

	private int[] getIds(DBBuffer[] buffers) {
		int[] ids = new int[buffers.length];
		for (int i = 0; i < ids.length; i++) {
			ids[i] = buffers[i].getId();
		}
		return ids;
	}

	private DBBuffer[] createLayeredBuffers(DBBuffer[] buffers) throws IOException {
		DBBuffer[] layeredBuffers = new DBBuffer[buffers.length];
		for (int i = 0; i < buffers.length; i++) {
			layeredBuffers[i] = handle.createBuffer(buffers[i]);
		}
		return layeredBuffers;
	}

	private DBBuffer[] createBuffers(long size, InputStream is) throws IOException {
		int maxBufSize = getMaxBufferSize();
		int bufCount = (int) (size / maxBufSize);
		int sizeLastBuf = (int) (size % maxBufSize);

		// there is a remainder then we have one additional buffer
		if (sizeLastBuf > 0) {
			bufCount++;
		}
		else {
			// divides evenly, so sizeLastBuf is full maxBuffSize
			sizeLastBuf = maxBufSize;
		}

		DBBuffer[] buffers = new DBBuffer[bufCount];
		for (int i = 0; i < bufCount - 1; i++) {
			buffers[i] = handle.createBuffer(maxBufSize);
		}
		buffers[bufCount - 1] = handle.createBuffer(sizeLastBuf);

		try {
			for (DBBuffer buffer : buffers) {
				buffer.fill(is);
			}
		}
		catch (IOCancelledException e) {
			for (DBBuffer buffer : buffers) {
				buffer.delete();
			}
			throw e;
		}
		return buffers;

	}
}
