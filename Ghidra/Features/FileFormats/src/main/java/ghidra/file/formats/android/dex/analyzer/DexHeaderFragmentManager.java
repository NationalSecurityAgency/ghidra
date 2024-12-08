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
package ghidra.file.formats.android.dex.analyzer;

import ghidra.app.util.importer.MessageLog;
import ghidra.file.formats.android.dex.format.CodeItem;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * A class to manage DEX fragment creation.
 * Allows address ranges to coalesce before being created.
 * Fragment creation is slow, so support option to skip it.
 */
class DexHeaderFragmentManager {

	private Program program;
	private Address baseAddress;
	private FlatProgramAPI api;
	private boolean isCreateFragments;

	AddressSet classesAddressSet = new AddressSet();
	AddressSet classStaticValuesAddressSet = new AddressSet();
	AddressSet classDataAddressSet = new AddressSet();
	AddressSet codeItemAddressSet = new AddressSet();
	AddressSet encodedFieldsAddressSet = new AddressSet();
	AddressSet encodedMethodsAddressSet = new AddressSet();
	AddressSet debugInfoAddressSet = new AddressSet();
	AddressSet handlersAddressSet = new AddressSet();
	AddressSet tryAddressSet = new AddressSet();
	AddressSet annotationsAddressSet = new AddressSet();
	AddressSet classAnnotationsAddressSet = new AddressSet();
	AddressSet annotationFieldsAddressSet = new AddressSet();
	AddressSet annotationMethodsAddressSet = new AddressSet();
	AddressSet annotationParametersAddressSet = new AddressSet();
	AddressSet annotationItemAddressSet = new AddressSet();
	AddressSet interfacesAddressSet = new AddressSet();
	AddressSet methodsAddressSet = new AddressSet();
	AddressSet fieldsAddressSet = new AddressSet();
	AddressSet prototypesAddressSet = new AddressSet();
	AddressSet typesAddressSet = new AddressSet();
	AddressSet mapAddressSet = new AddressSet();
	AddressSet stringDataAddressSet = new AddressSet();
	AddressSet stringsDataSet = new AddressSet();

	AddressSet[] addressSets = new AddressSet[] {
		classesAddressSet, classStaticValuesAddressSet, classDataAddressSet,
		codeItemAddressSet,
		encodedFieldsAddressSet, encodedMethodsAddressSet,
		debugInfoAddressSet, handlersAddressSet, tryAddressSet,
		annotationsAddressSet, classAnnotationsAddressSet,
		annotationFieldsAddressSet, annotationMethodsAddressSet,
		annotationParametersAddressSet, annotationItemAddressSet,
		interfacesAddressSet, methodsAddressSet, fieldsAddressSet,
		prototypesAddressSet, typesAddressSet, mapAddressSet,
		stringDataAddressSet, stringsDataSet,
	};

	private String[] addressSetNames = new String[] {
		"classes", "class_static_values", "class_data", CodeItem.CODE_ITEM,
		"encoded_fields", "encoded_methods", "debug_info",
		"handlers", "try", "annotations", "class_annotations",
		"annotation_fields", "annotation_methods", "annotation_parameters", "annotation_item",
		"interfaces", "methods", "fields", "prototypes", "types", "map", "string_data", "strings",
	};

	DexHeaderFragmentManager(Program program, Address baseAddress, FlatProgramAPI api,
			boolean isCreateFragments) {
		this.program = program;
		this.baseAddress = baseAddress;
		this.api = api;
		this.isCreateFragments = isCreateFragments;
	}

	void createFragments(TaskMonitor monitor, MessageLog log) throws CancelledException {
		if (!isCreateFragments) {
			return;
		}
		monitor.initialize(addressSetNames.length);
		for (int i = 0; i < addressSetNames.length; i++) {
			createFragment(addressSetNames[i], addressSets[i], monitor, log);
		}
	}

	void createFragment(String fragmentName, AddressSet addressSet, TaskMonitor monitor,
			MessageLog log) throws CancelledException {

		if (!isCreateFragments) {
			return;
		}
		monitor.incrementProgress(1);
		monitor.checkCancelled();
		monitor.setMessage("DEX: creating fragment: " + fragmentName + " ...");
		try {
			ProgramModule module = program.getListing().getDefaultRootModule();
			ProgramFragment fragment = api.getFragment(module, fragmentName);
			if (fragment == null) {
				fragment = module.createFragment(fragmentName);
			}
			for (AddressRange range : addressSet) {
				monitor.checkCancelled();
				fragment.move(range.getMinAddress(), range.getMaxAddress());
			}
		}
		catch (Exception e) {
			log.appendMsg(e.getMessage());
		}
	}

	void createInitialFragments(DexHeader header, TaskMonitor monitor) throws Exception {
		if (!isCreateFragments) {
			return;
		}
		monitor.setMessage("DEX: creating fragments");
		if (header.getDataSize() > 0) {
			Address start = baseAddress.add(header.getDataOffset());
			try {
				api.createFragment("data", start, header.getDataSize());
			}
			catch (NotFoundException e) {
				//ignore, case for incomplete CDEX
			}
		}
	}

	void createHeaderFragment(Address headerAddress, DataType headerDataType)
			throws DuplicateNameException, NotFoundException {

		if (!isCreateFragments) {
			return;
		}
		api.createFragment("header", headerAddress, headerDataType.getLength());
	}
}
