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
package ghidra.file.formats.android.dex.format;

import ghidra.app.util.bin.*;
import ghidra.file.formats.android.dex.util.DexUtil;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

public class ClassDefItem implements StructConverter {

	private int classIndex;
	private int accessFlags;
	private int superClassIndex;
	private int interfacesOffset;
	private int sourceFileIndex;
	private int annotationsOffset;
	private int classDataOffset;
	private int staticValuesOffset;

	private TypeList _interfaces;
	private AnnotationsDirectoryItem _annotationsDirectoryItem;
	private ClassDataItem _classDataItem;
	private EncodedArrayItem _staticValues;

	public ClassDefItem(BinaryReader reader, DexHeader dexHeader) throws IOException {
		classIndex = reader.readNextInt();
		accessFlags = reader.readNextInt();
		superClassIndex = reader.readNextInt();
		interfacesOffset = reader.readNextInt();
		sourceFileIndex = reader.readNextInt();
		annotationsOffset = reader.readNextInt();
		classDataOffset = reader.readNextInt();
		staticValuesOffset = reader.readNextInt();

		if (interfacesOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(interfacesOffset, dexHeader));
				_interfaces = new TypeList(reader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}

		if (annotationsOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(annotationsOffset, dexHeader));
				_annotationsDirectoryItem = new AnnotationsDirectoryItem(reader, dexHeader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}

		if (classDataOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(classDataOffset, dexHeader));
				_classDataItem = new ClassDataItem(reader, dexHeader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}

		if (staticValuesOffset > 0) {
			long oldIndex = reader.getPointerIndex();
			try {
				reader.setPointerIndex(DexUtil.adjustOffset(staticValuesOffset, dexHeader));
				_staticValues = new EncodedArrayItem(reader);
			}
			finally {
				reader.setPointerIndex(oldIndex);
			}
		}
	}

	public int getClassIndex() {
		return classIndex;
	}

	public int getAccessFlags() {
		return accessFlags;
	}

	public int getSuperClassIndex() {
		return superClassIndex;
	}

	public int getInterfacesOffset() {
		return interfacesOffset;
	}

	public int getSourceFileIndex() {
		return sourceFileIndex;
	}

	/**
	 * NOTE: For CDEX files, this value is relative to DataOffset in DexHeader
	 * @return the relative offset to annotations
	 */
	public int getAnnotationsOffset() {
		return annotationsOffset;
	}

	public int getClassDataOffset() {
		return classDataOffset;
	}

	public int getStaticValuesOffset() {
		return staticValuesOffset;
	}

	public TypeList getInterfaces() {
		return _interfaces;
	}

	public AnnotationsDirectoryItem getAnnotationsDirectoryItem() {
		return _annotationsDirectoryItem;
	}

	public ClassDataItem getClassDataItem() {
		return _classDataItem;
	}

	public EncodedArrayItem getStaticValues() {
		return _staticValues;
	}

	@Override
	public DataType toDataType() throws DuplicateNameException, IOException {
		DataType dataType = StructConverterUtil.toDataType(ClassDefItem.class);
		dataType.setCategoryPath(new CategoryPath("/dex"));
		return dataType;
	}

	public String toString(DexHeader header, int index, TaskMonitor monitor)
			throws CancelledException {
		StringBuilder builder = new StringBuilder();
		if (index != -1) {
			builder.append("Class Index: 0x" + Integer.toHexString(index) + "\n");
		}
		builder.append(
			"Class: " + DexUtil.convertTypeIndexToString(header, getClassIndex()) + "\n");
		builder.append("Class Access Flags:\n" + AccessFlags.toString(getAccessFlags()) + "\n");
		builder.append(
			"Superclass: " + DexUtil.convertTypeIndexToString(header, getSuperClassIndex()) + "\n");

		if (getInterfacesOffset() > 0) {
			builder.append("Interfaces: " + "\n");
			TypeList interfaces = getInterfaces();
			for (TypeItem type : interfaces.getItems()) {
				monitor.checkCanceled();
				builder.append(
					"\t" + DexUtil.convertTypeIndexToString(header, type.getType()) + "\n");
			}
		}

		if (getSourceFileIndex() > 0) {
			builder.append(
				"Source File: " + DexUtil.convertToString(header, getSourceFileIndex()) + "\n");
		}

		return builder.toString();
	}
}
