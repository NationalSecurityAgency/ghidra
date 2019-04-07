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
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.util.exception.AssertException;

class VarnodeTableModel extends AbstractGTableModel<VarnodeInfo> {
	private List<VarnodeCol> columns;
	private List<VarnodeInfo> varnodes;
	private StorageAddressModel storageModel;

	VarnodeTableModel(StorageAddressModel storageModel) {
		this.varnodes = new ArrayList<>(storageModel.getVarnodes());
		this.storageModel = storageModel;
		columns = new ArrayList<>();
		columns.add(new TypeColumn());
		columns.add(new LocationColumn());
		columns.add(new SizeColumn());
	}

	@Override
	public String getName() {
		return "Varnodes";
	}

	@Override
	public List<VarnodeInfo> getModelData() {
		return varnodes;
	}

	@Override
	public Object getColumnValueForRow(VarnodeInfo varnode, int columnIndex) {
		return columns.get(columnIndex).getValueForRow(varnode);
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		VarnodeInfo param = varnodes.get(rowIndex);
		VarnodeCol varnodeCol = columns.get(columnIndex);
		varnodeCol.setValue(param, aValue);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getColumnClass();
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

	private abstract class VarnodeCol {
		private String name;
		private boolean isEditable;
		private Class<?> classType;
		private int preferredSize;

		public VarnodeCol(String name, int preferredSize, Class<?> classType, boolean isEditable) {
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

		public void setValue(VarnodeInfo varnode, Object aValue) {
			// do nothing by default
		}

		public abstract Object getValueForRow(VarnodeInfo varnode);

		public boolean isCellEditable(int rowIndex) {
			return isEditable;
		}

		public String getName() {
			return name;
		}
	}

	private class TypeColumn extends VarnodeCol {

		public TypeColumn() {
			super("Type", 60, VarnodeType.class, true);
		}

		@Override
		public Object getValueForRow(VarnodeInfo varnode) {
			return varnode.getType();
		}

		@Override
		public void setValue(VarnodeInfo varnode, Object aValue) {
			storageModel.setVarnodeType(varnode, (VarnodeType) aValue);
		}
	}

	private class LocationColumn extends VarnodeCol {

		public LocationColumn() {
			super("Location", 60, Address.class, true);
		}

		@Override
		public Object getValueForRow(VarnodeInfo varnode) {
			Register register = varnode.getRegister();
			return register != null ? register : varnode.getAddress();
		}

		@Override
		public void setValue(VarnodeInfo varnode, Object aValue) {
			if (aValue == null) {
				return;
			}
			if (aValue instanceof Address) {
				storageModel.setVarnode(varnode, (Address) aValue, varnode.getSize());
			}
			else if (aValue instanceof Register) {
				storageModel.setVarnode(varnode, (Register) aValue);
			}
			else if (aValue instanceof String) {
				storageModel.setVarnode(varnode, (String) aValue);
			}
			else {
				throw new AssertException("Unexpected edit value");
			}
		}
	}

	private class SizeColumn extends VarnodeCol {

		public SizeColumn() {
			super("Size", 60, Integer.class, true);
		}

		@Override
		public Object getValueForRow(VarnodeInfo varnode) {
			return varnode.getSize();
		}

		@Override
		public void setValue(VarnodeInfo varnode, Object aValue) {
			if (aValue == null) {
				return;
			}
			Address address = varnode.getAddress();
			int size = (Integer) aValue;
			if (address != null) {
				Register reg = varnode.getRegister();
				if (reg != null && reg.isBigEndian()) {
					// adjust big endian register address
					int s = Math.min(reg.getMinimumByteSize(), size);
					address = reg.getAddress().add(reg.getMinimumByteSize() - s);
				}
			}
			storageModel.setVarnode(varnode, address, size);
		}
	}

	public List<VarnodeInfo> getVarnodes() {
		return varnodes;
	}

	public void setVarnodes(List<VarnodeInfo> varnodeList) {
		varnodes.clear();
		varnodes.addAll(varnodeList);
		fireTableDataChanged();
	}
}
