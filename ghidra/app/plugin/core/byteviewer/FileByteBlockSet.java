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
package ghidra.app.plugin.core.byteviewer;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.core.format.*;

/**
 * ByteBlockSet for a File object.
 */
class FileByteBlockSet implements ByteBlockSet {

	private FileByteBlock block;
	private List<EditInfo> changeList;

	FileByteBlockSet(File file) throws IOException {
		FileInputStream fis = new FileInputStream(file);
		byte[] bytes = new byte[(int) file.length()];
		fis.read(bytes);
		fis.close();
		block = new FileByteBlock(bytes);
		changeList = new ArrayList<EditInfo>();
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#dispose()
	 */
	@Override
	public void dispose() {
		block = null;
		changeList = null;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#getActiveObject(ghidra.app.plugin.core.format.ByteBlock, int)
	 */
	public Object getActiveObject(ByteBlock activeBlock, int offset) {
		// not applicable to this type of ByteBlockSet
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#getBlocks()
	 */
	@Override
	public ByteBlock[] getBlocks() {
		return new ByteBlock[] { block };
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#getPluginEvent(java.lang.String, ghidra.app.plugin.core.format.ByteBlock, int)
	 */
	@Override
	public ProgramLocationPluginEvent getPluginEvent(String source, ByteBlock activeBlock,
			BigInteger offset, int column) {
		// not applicable to this type of ByteBlockSet
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#getPluginEvent(java.lang.String, ghidra.app.plugin.core.format.ByteBlockSelection)
	 */
	@Override
	public ProgramSelectionPluginEvent getPluginEvent(String source, ByteBlockSelection selection) {
		// not applicable to this type of ByteBlockSet
		return null;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#isChanged(ghidra.app.plugin.core.format.ByteBlock, int, int)
	 */
	@Override
	public boolean isChanged(ByteBlock activeBlock, BigInteger bigIndex, int length) {
		int index = bigIndex.intValue();
		for (int i = 0; i < length; i++) {
			if (contains(index + i)) {
				return true;
			}
		}
		return false;
	}

	/* (non-Javadoc)
	 * @see ghidra.app.plugin.core.format.ByteBlockSet#notifyByteEditing(ghidra.app.plugin.core.format.ByteBlock, int, byte[], byte[])
	 */
	@Override
	public void notifyByteEditing(ByteBlock activeBlock, BigInteger bigIndex, byte[] oldValue,
			byte[] newValue) {
		int index = bigIndex.intValue();

		for (int i = 0; i < oldValue.length; i++) {
			if (oldValue[i] == newValue[i]) {
				continue;
			}
			EditInfo newedit = new EditInfo(index + i);
			changeList.add(newedit);
		}

	}

	void save(String pathname) throws IOException {
		FileOutputStream fos = new FileOutputStream(new File(pathname));

		byte[] buf = block.getBytes();
		try {
			fos.write(buf);
		}
		finally {
			fos.close();
		}
		block = new FileByteBlock(buf);
		changeList = new ArrayList<EditInfo>();
	}

	private boolean contains(int index) {
		for (int i = 0; i < changeList.size(); i++) {
			EditInfo info = changeList.get(i);
			if (index == info.index) {
				return true;
			}
		}
		return false;
	}

	private class EditInfo {
		private int index;

		EditInfo(int index) {
			this.index = index;
		}
	}
}
