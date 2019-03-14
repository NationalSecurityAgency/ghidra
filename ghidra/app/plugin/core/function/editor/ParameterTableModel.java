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
package ghidra.app.plugin.core.function.editor;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.AbstractGTableModel;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.VariableStorage;

class ParameterTableModel extends AbstractGTableModel<FunctionVariableData> {
	private List<ParamCol> columns;
	private List<FunctionVariableData> rowDataList = new ArrayList<>();
	private FunctionEditorModel functionModel;
	private boolean canCustomizeStorage;

	ParameterTableModel(FunctionEditorModel functionModel) {
		this.functionModel = functionModel;

		setParameters(functionModel.getParameters(), functionModel.getFormalReturnType(),
			functionModel.getReturnStorage());

		columns = new ArrayList<>();
		columns.add(new ParameterIndexColumn());
		columns.add(new DataTypeColumn());
		columns.add(new NameColumn());
		columns.add(new StorageColumn());
	}

	@Override
	public String getName() {
		return "Parameters";
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getColumnClass();
	}

	@Override
	public List<FunctionVariableData> getModelData() {
		return rowDataList;
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return columns.get(columnIndex).isCellEditable(rowIndex);
	}

	@Override
	public int getPreferredColumnWidth(int columnIndex) {
		return columns.get(columnIndex).getPreferredSize();
	}

	@Override
	public String getColumnName(int column) {
		return columns.get(column).getName();
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		FunctionVariableData rowData = rowDataList.get(rowIndex);
		ParamCol paramCol = columns.get(columnIndex);
		paramCol.setValue(rowData, aValue);
	}

	@Override
	public Object getColumnValueForRow(FunctionVariableData rowData, int columnIndex) {
		return columns.get(columnIndex).getValueForRow(rowData);
	}

	public List<ParamInfo> getParameters() {
		List<ParamInfo> list = new ArrayList<>();
		for (FunctionVariableData rowData : rowDataList) {
			if (rowData instanceof ParameterRowData) {
				list.add(((ParameterRowData) rowData).getParamInfo());
			}
		}
		return list;
	}

	public void setParameters(List<ParamInfo> parameterList, DataType returnDataType,
			VariableStorage returnStorage) {
		rowDataList.clear();
		rowDataList.add(new ReturnRowData(returnDataType, returnStorage));
		List<ParamInfo> parameters = functionModel.getParameters();
		for (ParamInfo paramInfo : parameters) {
			rowDataList.add(new ParameterRowData(paramInfo));
		}
		fireTableDataChanged();
	}

	private abstract class ParamCol {
		private String name;
		private boolean isEditable;
		private Class<?> classType;
		private int preferredSize;

		public ParamCol(String name, int preferredSize, Class<?> classType, boolean isEditable) {
			this.name = name;
			this.preferredSize = preferredSize;
			this.isEditable = isEditable;
			this.classType = classType;
		}

		public int getPreferredSize() {
			return preferredSize;
		}

		public Class<?> getColumnClass() {
			return classType;
		}

		public void setValue(FunctionVariableData rowData, Object aValue) {
			// do nothing by default
		}

		public abstract Object getValueForRow(FunctionVariableData rowDatas);

		public boolean isCellEditable(int rowIndex) {
			return isEditable;
		}

		public String getName() {
			return name;
		}
	}

	private class ParameterIndexColumn extends ParamCol {

		public ParameterIndexColumn() {
			super("Index", 20, Object.class, false);
		}

		@Override
		public Object getValueForRow(FunctionVariableData rowData) {
			return rowData.getIndex();
		}
	}

	private class DataTypeColumn extends ParamCol {

		public DataTypeColumn() {
			super("Datatype", 140, DataType.class, true);
		}

		@Override
		public boolean isCellEditable(int rowIndex) {
			// may not edit auto-param data-type
			FunctionVariableData rowData = getRowObject(rowIndex);
			VariableStorage storage = rowData.getStorage();
			return !storage.isAutoStorage();
		}

		@Override
		public Object getValueForRow(FunctionVariableData rowData) {
			return rowData.getFormalDataType();
		}

		@Override
		public void setValue(FunctionVariableData rowData, Object aValue) {
			rowData.setFormalDataType((DataType) aValue);
		}
	}

	private class NameColumn extends ParamCol {

		public NameColumn() {
			super("Name", 140, String.class, true);
		}

		@Override
		public boolean isCellEditable(int rowIndex) {
			// may not edit return name (row 0) or auto-param names
			FunctionVariableData rowData = getRowObject(rowIndex);
			VariableStorage storage = rowData.getStorage();
			return rowIndex != 0 && !storage.isAutoStorage();
		}

		@Override
		public Object getValueForRow(FunctionVariableData rowData) {
			return rowData.getName();
		}

		@Override
		public void setValue(FunctionVariableData rowData, Object aValue) {
			rowData.setName(((String) aValue).trim());
		}
	}

	private class StorageColumn extends ParamCol {

		public StorageColumn() {
			super("Storage", 140, VariableStorage.class, true);
		}

		@Override
		public boolean isCellEditable(int rowIndex) {
			return canCustomizeStorage;
		}

		@Override
		public Object getValueForRow(FunctionVariableData rowData) {
			return rowData.getStorage();
		}

		@Override
		public void setValue(FunctionVariableData rowData, Object aValue) {
			rowData.setStorage((VariableStorage) aValue);
		}
	}

	public void setAllowStorageEditing(boolean canCustomizeStorage) {
		this.canCustomizeStorage = canCustomizeStorage;
	}

	class ParameterRowData implements FunctionVariableData {
		private ParamInfo param;

		ParameterRowData(ParamInfo paramInfo) {
			this.param = paramInfo;
		}

		public ParamInfo getParamInfo() {
			return param;
		}

		@Override
		public Integer getIndex() {
			return param.getOrdinal() + 1;
		}

		@Override
		public VariableStorage getStorage() {
			return param.getStorage();
		}

		@Override
		public String getName() {
			return param.getName();
		}

		@Override
		public DataType getFormalDataType() {
			return param.getFormalDataType();
		}

		@Override
		public void setFormalDataType(DataType dataType) {
			functionModel.setParameterFormalDataType(param, dataType);
		}

		@Override
		public void setName(String name) {
			functionModel.setParameterName(param, name);
		}

		@Override
		public void setStorage(VariableStorage storage) {
			functionModel.setParameterStorage(param, storage);
		}
	}

	class ReturnRowData implements FunctionVariableData {
		private DataType formalDataType;
		private VariableStorage storage;

		ReturnRowData(DataType formalDataType, VariableStorage storage) {
			this.formalDataType = formalDataType;
			this.storage = storage;
		}

		@Override
		public Integer getIndex() {
			return null;
		}

		@Override
		public VariableStorage getStorage() {
			return storage;
		}

		@Override
		public String getName() {
			return "<RETURN>";
		}

		@Override
		public DataType getFormalDataType() {
			return formalDataType;
		}

		@Override
		public void setFormalDataType(DataType dataType) {
			functionModel.setFormalReturnType(dataType);
		}

		@Override
		public void setStorage(VariableStorage storage) {
			functionModel.setReturnStorage(storage);
		}

		@Override
		public void setName(String name) {
			// TODO Auto-generated method stub

		}
	}
}
