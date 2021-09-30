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

import java.awt.Dimension;
import java.awt.FontMetrics;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import docking.widgets.fieldpanel.Layout;
import docking.widgets.fieldpanel.LayoutModel;
import docking.widgets.fieldpanel.field.EmptyTextField;
import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.listener.IndexMapper;
import docking.widgets.fieldpanel.listener.LayoutModelListener;
import docking.widgets.fieldpanel.support.SingleRowLayout;
import ghidra.app.plugin.core.format.DataFormatModel;

/**
 * Implements the LayoutModel for ByteViewer Components.
 */
public class ByteViewerLayoutModel implements LayoutModel {
	private int width;
	private IndexMap indexMap;
	private List<LayoutModelListener> listeners;
	private FieldFactory[] factorys;
	private BigInteger numIndexes;

	public ByteViewerLayoutModel() {
		factorys = new FieldFactory[0];
		listeners = new ArrayList<LayoutModelListener>(1);
		numIndexes = BigInteger.ZERO;
	}

	void dispose() {
		indexMap = null;
		listeners = null;
		factorys = null;
	}

	void setFactorys(FieldFactory[] fieldFactorys, DataFormatModel dataModel, int margin) {
		factorys = new FieldFactory[fieldFactorys.length];

		int x = margin;
		int defaultGroupSizeSpace = 1;
		for (int i = 0; i < factorys.length; i++) {
			factorys[i] = fieldFactorys[i];
			factorys[i].setStartX(x);
			x += factorys[i].getWidth();
			// add in space between groups
			if (((i + 1) % defaultGroupSizeSpace) == 0) {
				x += margin * dataModel.getUnitDelimiterSize();
			}
		}
		width = x - margin * dataModel.getUnitDelimiterSize() + margin;
		layoutChanged();
	}

	void setIndexMap(IndexMap indexMap) {
		if (indexMap == this.indexMap) {
			return;
		}
		this.indexMap = indexMap;
		if (indexMap == null) {
			numIndexes = BigInteger.ZERO;
		}
		else {
			numIndexes = indexMap.getNumIndexes();
		}
		indexSetChanged();
	}

	public void indexSetChanged() {
		for (LayoutModelListener listener : listeners) {
			listener.modelSizeChanged(IndexMapper.IDENTITY_MAPPER);
		}
	}

	public void layoutChanged() {
		for (LayoutModelListener listener : listeners) {
			listener.dataChanged(BigInteger.ZERO, numIndexes);
		}
	}

	public void dataChanged(BigInteger startIndex, BigInteger endIndex) {
		for (LayoutModelListener listener : listeners) {
			listener.dataChanged(startIndex, endIndex);
		}
	}

	@Override
	public boolean isUniform() {
		return true;
	}

	@Override
	public Dimension getPreferredViewSize() {
		return new Dimension(width, 500);
	}

	/**
	 * Returns the total number of valid indexes.
	 */
	@Override
	public BigInteger getNumIndexes() {
		return numIndexes;
	}

	@Override
	public Layout getLayout(BigInteger index) {
		if (index.compareTo(numIndexes) >= 0) {
			return null;
		}
		List<Field> fields = new ArrayList<Field>(8);
		for (FieldFactory factory : factorys) {
			Field field = factory.getField(index);
			if (field != null) {
				fields.add(field);
			}
		}
		if (fields.size() == 0) {
			if (factorys.length > 0) {
				FontMetrics fm = factorys[0].getMetrics();
				int height = fm.getMaxAscent() + fm.getMaxDescent();
				fields.add(
					new EmptyTextField(height, factorys[0].getStartX(), 0, factorys[0].getWidth()));
			}
			else {
				fields.add(new EmptyTextField(20, 0, 0, 10));
			}
		}
		Field[] fieldArray = new Field[fields.size()];
		fields.toArray(fieldArray);
		return new SingleRowLayout(fieldArray);
	}

	@Override
	public void removeLayoutModelListener(LayoutModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void addLayoutModelListener(LayoutModelListener listener) {
		listeners.add(listener);
	}

	/**
	 * @see docking.widgets.fieldpanel.LayoutModel#getIndexAfter(int)
	 */
	public int getIndexAfter(int index) {
		return index + 1;
	}

	@Override
	public BigInteger getIndexAfter(BigInteger index) {
		BigInteger nextIndex = index.add(BigInteger.ONE);
		if (nextIndex.compareTo(numIndexes) >= 0) {
			return null;
		}
		return nextIndex;
	}

	@Override
	public BigInteger getIndexBefore(BigInteger index) {
		if (index.compareTo(numIndexes) > 0) {
			return numIndexes.subtract(BigInteger.ONE);
		}
		BigInteger previousIndex = index.subtract(BigInteger.ONE);
		if (previousIndex.compareTo(BigInteger.ZERO) < 0) {
			return null;
		}
		return previousIndex;
	}

	@Override
	public void flushChanges() {
	}

}
