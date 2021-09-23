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
package ghidra.file.formats.android.art;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.util.bin.BinaryReader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public abstract class ArtImageSections {

	public final static int UNSUPPORTED_SECTION = -1;

	protected ArtHeader header;

	protected List<ArtImageSection> sectionList = new ArrayList<>();
	protected List<ArtFieldGroup> fieldGroupList = new ArrayList<>();
	protected List<ArtMethodGroup> methodGroupList = new ArrayList<>();

	protected List<ArtField> fieldList = new ArrayList<>();
	protected List<ArtMethod> methodList = new ArrayList<>();

	protected ArtImageSections(BinaryReader reader, ArtHeader header) {
		this.header = header;
	}

	/**
	 * Returns the section name for the given ordinal.
	 * For example, if sectionOrdinal is 0 then return "kSectionObjects".
	 * @param sectionOrdinal the original of the ART section
	 * @return the ART section name
	 */
	protected String getSectionName(int sectionOrdinal) {
		for (Field field : getClass().getDeclaredFields()) {
			if (field.getName().startsWith("kSection")) {
				try {
					Object value = field.get(null);
					if ((int) value == sectionOrdinal) {
						return field.getName();
					}
				}
				catch (Exception e) {
					//ignore
				}
			}
		}
		return "unknown_section_0x" + Integer.toHexString(sectionOrdinal);
	}

	public abstract int get_kSectionObjects();

	public abstract int get_kSectionArtFields();

	public abstract int get_kSectionArtMethods();

	public abstract int get_kSectionRuntimeMethods();

	public abstract int get_kSectionImTables();

	public abstract int get_kSectionIMTConflictTables();

	public abstract int get_kSectionDexCacheArrays();

	public abstract int get_kSectionInternedStrings();

	public abstract int get_kSectionClassTable();

	public abstract int get_kSectionStringReferenceOffsets();

	public abstract int get_kSectionMetadata();

	public abstract int get_kSectionImageBitmap();

	public abstract int get_kSectionCount(); // Number of elements in enum.

	public final List<ArtImageSection> getSectionList() {
		return sectionList;
	}

	public final void parseSections(BinaryReader reader) throws IOException {
		for (int i = 0; i < get_kSectionCount(); ++i) {
			sectionList.add(new ArtImageSection(reader));
		}
	}

	public final void parse(BinaryReader reader) throws IOException {
		parseArtFields(reader);
		parseArtMethods(reader);
	}

	private void parseArtFields(BinaryReader reader) throws IOException {
		ArtImageSection kSectionArtFields = sectionList.get(get_kSectionArtFields());
		if (kSectionArtFields.getSize() > 0) {
			if (reader.length() > kSectionArtFields.getOffset()) {//out of bounds
				reader.setPointerIndex(kSectionArtFields.getOffset());
				while (reader.getPointerIndex() < Integer
						.toUnsignedLong(kSectionArtFields.getEnd())) {
					if (ArtConstants.VERSION_MARSHMALLOW_RELEASE.equals(header.getVersion())) {
						ArtField field = new ArtField(reader);
						fieldList.add(field);
					}
					else {
						ArtFieldGroup group = new ArtFieldGroup(reader);
						fieldGroupList.add(group);
					}
				}
			}
		}
	}

	private void parseArtMethods(BinaryReader reader) throws IOException {
		ArtImageSection kSectionArtMethods = sectionList.get(get_kSectionArtMethods());
		if (kSectionArtMethods.getSize() > 0) {
			if (reader.length() > kSectionArtMethods.getOffset()) {//out of bounds
				reader.setPointerIndex(kSectionArtMethods.getOffset());
				while (reader.getPointerIndex() < Integer
						.toUnsignedLong(kSectionArtMethods.getEnd())) {
					if (ArtConstants.VERSION_MARSHMALLOW_RELEASE.equals(header.getVersion())) {
						ArtMethod method =
							new ArtMethod(reader, header.getPointerSize(), header.getVersion());
						methodList.add(method);
					}
					else {
						ArtMethodGroup group = new ArtMethodGroup(reader, header.getPointerSize(),
							header.getVersion());
						methodGroupList.add(group);
					}
				}
			}
		}
	}

	public void markup(Program program, TaskMonitor monitor) throws Exception {
		markupSections(program, monitor);
		markupFields(program, monitor);
		markupMethods(program, monitor);
		markupImTables(program, monitor);
		markupIMTConflictTables(program, monitor);
		markupRuntimeMethods(program, monitor);
		markupDexCacheArrays(program, monitor);
		markupInternedStrings(program, monitor);
		markupClassTables(program, monitor);
	}

	private void markupSections(Program program, TaskMonitor monitor) throws Exception {
		monitor.setMessage("ART - markup sections...");
		monitor.setProgress(0);
		monitor.setMaximum(sectionList.size());

		for (int i = 0; i < sectionList.size(); ++i) {
			monitor.checkCanceled();
			monitor.incrementProgress(1);

			ArtImageSection section = sectionList.get(i);

			if (section.getSize() == 0) {
				continue;
			}
			String name = getSectionName(i);
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());
			program.getSymbolTable().createLabel(address, name, SourceType.ANALYSIS);
			program.getListing()
					.setComment(address, CodeUnit.PLATE_COMMENT, "Size: " + section.getSize());

			createFragment(program, address, section, name, monitor);
		}
	}

	private void markupFields(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionArtFields() == UNSUPPORTED_SECTION) {
			return;
		}

		monitor.setMessage("ART - markup fields...");
		monitor.setProgress(0);
		monitor.setMaximum(fieldList.size());

		ArtImageSection section = sectionList.get(get_kSectionArtFields());

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			for (int i = 0; i < fieldList.size(); ++i) {
				monitor.checkCanceled();
				ArtField field = fieldList.get(i);
				DataType dataType = field.toDataType();
				program.getListing().createData(address, dataType);

				String comment =
					"Declaring Class: 0x" + Integer.toHexString(field.getDeclaringClass());
				program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);

				address = address.add(dataType.getLength());

				monitor.incrementProgress(1);
			}
		}

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());
			for (int i = 0; i < fieldGroupList.size(); ++i) {
				monitor.checkCanceled();
				ArtFieldGroup fieldGroup = fieldGroupList.get(i);
				DataType dataType = fieldGroup.toDataType();
				program.getListing().createData(address, dataType);
				if (fieldGroup.getFieldCount() > 0) {
					ArtField artField = fieldGroup.getFieldList().get(0);
					String comment =
						"Declaring Class: 0x" + Integer.toHexString(artField.getDeclaringClass());
					program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
				}
				address = address.add(dataType.getLength());

				monitor.incrementProgress(1);
			}
		}
	}

	private void markupMethods(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionArtMethods() == UNSUPPORTED_SECTION) {
			return;
		}

		monitor.setMessage("ART - markup methods...");
		monitor.setProgress(0);
		monitor.setMaximum(methodGroupList.size());

		ArtImageSection section = sectionList.get(get_kSectionArtMethods());

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());
			for (int i = 0; i < methodList.size(); ++i) {
				monitor.checkCanceled();

				ArtMethod method = methodList.get(i);
				DataType dataType = method.toDataType();
				program.getListing().createData(address, dataType);
				String comment =
					"Declaring Class: 0x" + Integer.toHexString(method.getDeclaringClass());
				program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);

				address = address.add(dataType.getLength());

				monitor.incrementProgress(1);
			}
		}

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());
			for (int i = 0; i < methodGroupList.size(); ++i) {
				monitor.checkCanceled();

				ArtMethodGroup methodGroup = methodGroupList.get(i);
				DataType dataType = methodGroup.toDataType();
				program.getListing().createData(address, dataType);
				if (methodGroup.getMethodCount() > 0) {
					ArtMethod artMethod = methodGroup.getMethodList().get(0);
					String comment =
						"Declaring Class: 0x" + Integer.toHexString(artMethod.getDeclaringClass());
					program.getListing().setComment(address, CodeUnit.PLATE_COMMENT, comment);
				}
				address = address.add(dataType.getLength());

				monitor.incrementProgress(1);
			}
		}
	}

	/**
	 * Interface Methods Tables
	 */
	private void markupImTables(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionImTables() == UNSUPPORTED_SECTION) {
			return;
		}
		ArtImageSection section = sectionList.get(get_kSectionImTables());

		monitor.setMessage("ART - markup IM tables...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		int pointerSize = header.getPointerSize();

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(pointerSize);

				createDataAt(program, address, pointerSize);
				address = address.add(pointerSize);
			}
		}
	}

	/**
	 * IMT Conflict Tables
	 */
	private void markupIMTConflictTables(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionIMTConflictTables() == UNSUPPORTED_SECTION) {
			return;
		}

		ArtImageSection section = sectionList.get(get_kSectionIMTConflictTables());

		monitor.setMessage("ART - markup IMT conflict tables...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		int pointerSize = header.getPointerSize();

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(pointerSize);

				createDataAt(program, address, pointerSize);
				address = address.add(pointerSize);
			}
		}
	}

	private void markupRuntimeMethods(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionRuntimeMethods() == UNSUPPORTED_SECTION) {
			return;
		}

		ArtImageSection section = sectionList.get(get_kSectionRuntimeMethods());

		monitor.setMessage("ART - markup runtime methods...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		int pointerSize = header.getPointerSize();
		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(pointerSize);

				createDataAt(program, address, pointerSize);
				address = address.add(pointerSize);
			}
		}
	}

	private void markupDexCacheArrays(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionDexCacheArrays() == UNSUPPORTED_SECTION) {
			return;
		}

		ArtImageSection section = sectionList.get(get_kSectionDexCacheArrays());

		monitor.setMessage("ART - markup dex cache arrays...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(4);

				createDataAt(program, address, 4);
				address = address.add(4);
			}
		}
	}

	private void markupInternedStrings(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionInternedStrings() == UNSUPPORTED_SECTION) {
			return;
		}

		ArtImageSection section = sectionList.get(get_kSectionInternedStrings());

		monitor.setMessage("ART - markup interned strings...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(4);

				createDataAt(program, address, 4);
				address = address.add(4);
			}
		}
	}

	private void markupClassTables(Program program, TaskMonitor monitor) throws Exception {
		if (get_kSectionClassTable() == UNSUPPORTED_SECTION) {
			return;
		}

		ArtImageSection section = sectionList.get(get_kSectionClassTable());

		monitor.setMessage("ART - markup class tables...");
		monitor.setProgress(0);
		monitor.setMaximum(section.getSize());

		if (section.getSize() > 0) {
			Address address =
				program.getMinAddress().getNewAddress(header.getImageBegin() + section.getOffset());

			if (!program.getMemory().contains(address)) {//outside of ART file
				return;
			}

			Address endAddress = address.add(section.getSize());
			while (address.compareTo(endAddress) < 0) {
				monitor.checkCanceled();
				monitor.incrementProgress(4);

				address = address.add(4);
			}
		}
	}

	private void createDataAt(Program program, Address address, int pointerSize) throws Exception {
		if (pointerSize == 4) {
			program.getListing().createData(address, new DWordDataType());
		}
		else if (pointerSize == 8) {
			program.getListing().createData(address, new QWordDataType());
		}
		else {
			throw new RuntimeException("invalid pointer size");
		}
	}

	private void createFragment(Program program, Address address, ArtImageSection section,
			String sectionName, TaskMonitor monitor) {
		try {
			ProgramModule rootModule = program.getListing().getDefaultRootModule();

			ProgramFragment fragment = null;
			for (Group group : rootModule.getChildren()) {
				if (group.getName().equals(sectionName)) {
					fragment = (ProgramFragment) group;
				}
			}
			if (fragment == null) {
				fragment = rootModule.createFragment(sectionName);
			}

			Address endAddress = address.add((Integer.toUnsignedLong(section.getSize()) - 1));
			if (sectionList.indexOf(section) == sectionList.size() - 1) {//last section might extend past the end of the program
				if (endAddress.compareTo(program.getMaxAddress()) > 0) {
					endAddress = program.getMaxAddress();
				}
			}
			fragment.move(address, endAddress);
		}
		catch (Exception e) {
			//ignore...
		}
	}
}
