/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.util.datastruct;

/**
 * Data table that keeps track of rows that are occupied.
 * 
 */
public class ManagedDataTable extends DataTable {
    private final static long serialVersionUID = 1;

    private BooleanArray occupied = new BooleanArray();
    private int maxRow;

    /** returns true if the given row contains an object
     * @param row the row in the table
     * @return true if the given row contains an object
     */
    public boolean hasRow(int row) {
        if (row < 0) {
            return false;
        }
        return occupied.get(row);
    }

	/**
	 * Returns the max row that contains data.
	 */
	public int getMaxRow() {
		return maxRow;
	}

    /** Removes the given row from the table.
     * @param row The row to be removed
     */
    @Override
    public void removeRow(int row) {
        if (occupied.get(row)) {
			super.removeRow(row);
            occupied.remove(row);
            if (row == maxRow) {
            	maxRow = 0;
            	for (int i = row ; i >= 0 ; --i) {
            		if (occupied.get(i)) {
            			maxRow = i;
            			break;
            		}
            	}
            }
        }
    }

    /** Stores a boolean value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putBoolean(int row, int col, boolean value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putBoolean(row, col, value);
    }

    /** Stores a byte value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putByte(int row, int col, byte value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
        super.putByte(row, col, value);
    }

    /** Stores a short value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putShort(int row, int col, short value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putShort(row, col, value);
    }

    /** Stores an int value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putInt(int row, int col, int value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putInt(row, col, value);
    }

    /** Stores a long value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putLong(int row, int col, long value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putLong(row, col, value);
    }
    /** Stores a double value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putDouble(int row, int col, double value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putDouble(row, col, value);
    }
    /** Stores a float value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putFloat(int row, int col, float value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putFloat(row, col, value);
    }

    /** Stores an String in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putString(int row, int col, String value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putString(row, col, value);
    }

    /** Stores an byte array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putByteArray(int row, int col, byte[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putByteArray(row, col, value);
    }

   /** Stores an short array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putShortArray(int row, int col, short[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putShortArray(row, col, value);
    }

    /** Stores an int array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putIntArray(int row, int col, int[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putIntArray(row, col, value);
    }

    /** Stores a float array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putFloatArray(int row, int col, float[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putFloatArray(row, col, value);

    }
    /** Stores a double array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putDoubleArray(int row, int col, double[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putDoubleArray(row, col, value);
    }

    /** Stores an long array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    @Override
    public void putLongArray(int row, int col, long[] value) {
    	maxRow = Math.max(maxRow, row);
        occupied.put(row,true);
		super.putLongArray(row, col, value);
    }

}

