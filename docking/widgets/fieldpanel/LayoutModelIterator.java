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
package docking.widgets.fieldpanel;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * An {@link Iterator} returning {@link Layout} objects that hides the details of using {@link LayoutModel}'s
 * indexing methods.
 */
public class LayoutModelIterator implements Iterator<Layout> {

	private LayoutModel layoutModel;
	private BigInteger index;
	private BigInteger lastIndex;

	public LayoutModelIterator(LayoutModel layoutModel) {
		this(layoutModel, BigInteger.ZERO);
	}

	public LayoutModelIterator(LayoutModel layoutModel, BigInteger startIndex) {
		this.layoutModel = layoutModel;
		this.index = startIndex;
	}

	/**
	 * Returns the LayoutModel index of the item that was just returned via {@link #next()}.
	 * 
	 * @return index of the last Layout item returned.
	 */
	public BigInteger getIndex() {
		return lastIndex;
	}

	/**
	 * Returns the LayoutModel index of the next item that will be returned via {@link #next()}.
	 * 
	 * @return index of the next Layout item returned, or null if no additional items are present
	 */
	public BigInteger getNextIndex() {
		return layoutModel.getIndexAfter(lastIndex);
	}

	/**
	 * Returns the LayoutModel index of the previous item that was returned via {@link #next()}.
	 * 
	 * @return index of the previous Layout item returned, or null if this iterator hasn't been
	 * used yet.
	 */
	public BigInteger getPreviousIndex() {
		return layoutModel.getIndexBefore(lastIndex);
	}

	@Override
	public boolean hasNext() {
		return index != null;
	}

	@Override
	public Layout next() {
		Layout result = layoutModel.getLayout(index);
		lastIndex = index;
		index = layoutModel.getIndexAfter(index);
		return result;
	}

}
