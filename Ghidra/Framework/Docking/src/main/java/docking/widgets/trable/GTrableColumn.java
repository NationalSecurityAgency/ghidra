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
package docking.widgets.trable;

/**
 * Abstract base class for {@link GTrable} column objects in the {@link GTrableColumnModel}
 *
 * @param <R> the row object type
 * @param <C> the column value type
 */
public abstract class GTrableColumn<R, C> {
	private static final int DEFAULT_MIN_SIZE = 20;
	private static GTrableCellRenderer<Object> DEFAULT_RENDERER =
		new DefaultGTrableCellRenderer<>();

	private int startX;
	private int width;

	public GTrableColumn() {
		width = getPreferredWidth();
	}

	public int getWidth() {
		return width;
	}

	@SuppressWarnings("unchecked")
	public GTrableCellRenderer<C> getRenderer() {
		return (GTrableCellRenderer<C>) DEFAULT_RENDERER;
	}

	/**
	 * Returns the column value given the row object
	 * @param row the row object containing the data for the entire row
	 * @return the value to be displayed in this column
	 */
	public abstract C getValue(R row);

	protected int getPreferredWidth() {
		return 100;
	}

	void setWidth(int width) {
		this.width = width;
	}

	public int getMinWidth() {
		return DEFAULT_MIN_SIZE;
	}

	public boolean isResizable() {
		return true;
	}

	void setStartX(int x) {
		this.startX = x;
	}

	int getStartX() {
		return startX;
	}

}
