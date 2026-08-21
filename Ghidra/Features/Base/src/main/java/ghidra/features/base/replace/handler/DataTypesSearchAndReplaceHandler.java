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
package ghidra.features.base.replace.handler;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.features.base.quickfix.QuickFix;
import ghidra.features.base.replace.*;
import ghidra.features.base.replace.items.*;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * {@link SearchAndReplaceHandler} for handling search and replace for datatype names,
 * structure and union field names, structure and union field comments, enum value names,
 * and enum value comments.
 */
public class DataTypesSearchAndReplaceHandler extends SearchAndReplaceHandler {
	DataTypeSearchType nameType;
	DataTypeSearchType datatypeCommentsType;
	DataTypeSearchType fieldNameType;
	DataTypeSearchType enumValueNameType;

	public DataTypesSearchAndReplaceHandler() {
		nameType = new NameSearchType(this);
		datatypeCommentsType = new DataTypeCommentsSearchType(this);
		fieldNameType = new FieldNameSearchType(this);
		enumValueNameType = new EnumValueSearchType(this);

		addType(nameType);
		addType(datatypeCommentsType);
		addType(fieldNameType);
		addType(enumValueNameType);
	}

	@Override
	public void findAll(Program program, SearchAndReplaceQuery query,
			Accumulator<QuickFix> accumulator, TaskMonitor monitor) throws CancelledException {

		ProgramBasedDataTypeManager dataTypeManager = program.getDataTypeManager();
		List<DataType> allDataTypes = new ArrayList<>();
		dataTypeManager.getAllDataTypes(allDataTypes);

		monitor.initialize(allDataTypes.size(), "Searching DataTypes...");

		boolean doNames = query.containsSearchType(nameType);
		boolean doDatatypeComments = query.containsSearchType(datatypeCommentsType);
		boolean doFieldNames = query.containsSearchType(fieldNameType);
		boolean doEnumValueNames = query.containsSearchType(enumValueNameType);

		for (DataType dataType : allDataTypes) {
			monitor.increment();
			if (dataType instanceof Pointer || dataType instanceof Array) {
				continue;
			}
			if (doNames) {
				nameType.search(program, dataType, query, accumulator);
			}
			if (doDatatypeComments) {
				datatypeCommentsType.search(program, dataType, query, accumulator);
			}
			if (doFieldNames) {
				fieldNameType.search(program, dataType, query, accumulator);
			}
			if (doEnumValueNames) {
				enumValueNameType.search(program, dataType, query, accumulator);
			}
		}
	}

	private abstract static class DataTypeSearchType extends SearchType {
		public DataTypeSearchType(SearchAndReplaceHandler handler, String name,
				String description) {
			super(handler, name, description);
		}

		protected abstract void search(Program program, DataType dataType,
				SearchAndReplaceQuery query, Accumulator<QuickFix> accumulator);

	}

	private static class NameSearchType extends DataTypeSearchType {
		public NameSearchType(SearchAndReplaceHandler handler) {
			super(handler, "Datatypes", "Search and replace datatype names");
		}

		@Override
		protected void search(Program program, DataType dataType, SearchAndReplaceQuery query,
				Accumulator<QuickFix> accumulator) {

			Pattern searchPattern = query.getSearchPattern();
			Matcher matcher = searchPattern.matcher(dataType.getName());
			if (matcher.find()) {
				String newName = matcher.replaceAll(query.getReplacementText());
				RenameDataTypeQuickFix item =
					new RenameDataTypeQuickFix(program, dataType, newName);
				accumulator.add(item);
			}
		}

	}

	private static class FieldNameSearchType extends DataTypeSearchType {
		public FieldNameSearchType(SearchAndReplaceHandler handler) {
			super(handler, "Datatype Fields",
				"Search and replace structure and union member names");
		}

		@Override
		protected void search(Program program, DataType dataType, SearchAndReplaceQuery query,
				Accumulator<QuickFix> accumulator) {

			if (!(dataType instanceof Composite composite)) {
				return;
			}
			DataTypeComponent[] definedComponents = composite.getDefinedComponents();
			Pattern searchPattern = query.getSearchPattern();

			for (int i = 0; i < definedComponents.length; i++) {
				DataTypeComponent component = definedComponents[i];
				String name = getFieldName(component);
				Matcher matcher = searchPattern.matcher(name);
				if (matcher.find()) {
					String newName = matcher.replaceAll(query.getReplacementText());
					int ordinal = component.getOrdinal();
					QuickFix item =
						new RenameFieldQuickFix(program, composite, ordinal, name, newName);
					accumulator.add(item);
				}
			}
		}

		private String getFieldName(DataTypeComponent component) {
			String fieldName = component.getFieldName();
			return fieldName == null ? component.getDefaultFieldName() : fieldName;
		}
	}

	private static class DataTypeCommentsSearchType extends DataTypeSearchType {
		public DataTypeCommentsSearchType(SearchAndReplaceHandler handler) {
			super(handler, "Datatype Comments", "Search and replace comments on datatypes");
		}

		@Override
		protected void search(Program program, DataType dataType, SearchAndReplaceQuery query,
				Accumulator<QuickFix> accumulator) {
			searchDescriptions(program, dataType, query, accumulator);

			if (dataType instanceof Composite composite) {
				searchFieldComments(program, composite, query, accumulator);
			}
			else if (dataType instanceof Enum enumm) {
				searchEnumComments(program, enumm, query, accumulator);
			}
		}

		private void searchEnumComments(Program program, Enum enumm, SearchAndReplaceQuery query,
				Accumulator<QuickFix> accumulator) {
			String[] names = enumm.getNames();
			Pattern searchPattern = query.getSearchPattern();
			for (int i = 0; i < names.length; i++) {
				String valueName = names[i];
				String comment = enumm.getComment(valueName);
				Matcher matcher = searchPattern.matcher(comment);
				if (matcher.find()) {
					String newValueName = matcher.replaceAll(query.getReplacementText());
					QuickFix item =
						new UpdateEnumCommentQuickFix(program, enumm, valueName, newValueName);
					accumulator.add(item);
				}
			}
		}

		private void searchFieldComments(Program program, Composite composite,
				SearchAndReplaceQuery query, Accumulator<QuickFix> accumulator) {

			DataTypeComponent[] definedComponents = composite.getDefinedComponents();
			Pattern searchPattern = query.getSearchPattern();

			for (int i = 0; i < definedComponents.length; i++) {
				DataTypeComponent component = definedComponents[i];
				String comment = component.getComment();
				if (comment == null) {
					continue;
				}
				Matcher matcher = searchPattern.matcher(comment);
				if (matcher.find()) {
					String newComment = matcher.replaceAll(query.getReplacementText());
					QuickFix item =
						new UpdateFieldCommentQuickFix(program, composite, component.getFieldName(),
							component.getOrdinal(), comment, newComment);
					accumulator.add(item);
				}
			}
		}

		protected void searchDescriptions(Program program, DataType dataType,
				SearchAndReplaceQuery query, Accumulator<QuickFix> accumulator) {

			String description = getDescription(dataType);
			if (description == null || description.isBlank()) {
				return;
			}
			Pattern searchPattern = query.getSearchPattern();
			Matcher matcher = searchPattern.matcher(description);
			if (matcher.find()) {
				String newName = matcher.replaceAll(query.getReplacementText());
				UpdateDataTypeDescriptionQuickFix item =
					new UpdateDataTypeDescriptionQuickFix(program, dataType, newName);
				accumulator.add(item);
			}
		}

		private String getDescription(DataType dataType) {
			if (dataType instanceof Composite composite) {
				return composite.getDescription();
			}
			if (dataType instanceof Enum enumDataType) {
				return enumDataType.getDescription();
			}
			return null;
		}

	}

	private static class EnumValueSearchType extends DataTypeSearchType {
		public EnumValueSearchType(SearchAndReplaceHandler handler) {
			super(handler, "Enum Values", "Search and replace enum value names");
		}

		@Override
		protected void search(Program program, DataType dataType, SearchAndReplaceQuery query,
				Accumulator<QuickFix> accumulator) {

			if (!(dataType instanceof Enum enumm)) {
				return;
			}
			String[] names = enumm.getNames();
			Pattern searchPattern = query.getSearchPattern();

			for (int i = 0; i < names.length; i++) {
				String valueName = names[i];
				Matcher matcher = searchPattern.matcher(valueName);
				if (matcher.find()) {
					String newValueName = matcher.replaceAll(query.getReplacementText());
					QuickFix item =
						new RenameEnumValueQuickFix(program, enumm, valueName, newValueName);
					accumulator.add(item);
				}
			}
		}
	}

}
