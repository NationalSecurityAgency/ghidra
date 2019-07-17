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
import java.io.Serializable;

/**
 * Table for managing rows and columns of data.
 * 
 * 
 */
public class DataTable implements Serializable {
    private final static long serialVersionUID = 1;

    private Array[] dataColumns;
	
    /** Creates a new DataTable. */
	public DataTable() {
		dataColumns = new Array[2];
	}
    /** Removes the given row from the table.
     * @param row The row to be removed
     */
    public void removeRow(int row) {
        for(int i=0;i<dataColumns.length;i++) {
            if (dataColumns[i] != null) {
                dataColumns[i].remove(row);
            }
        }
    }
	/**
	 * Copy one row to another row.
	 * @param row source row
	 * @param table table containing the data
	 * @param toRow destination row
	 */
    public void copyRowTo(int row, DataTable table, int toRow) {
        for(int i=0;i<dataColumns.length;i++) {
        	if (dataColumns[i] != null) {
	            dataColumns[i].copyDataTo(row, table, toRow, i);
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
    public void putBoolean(int row, int col, boolean value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        BooleanArray ba = null;
        if (dataColumns[col] == null) {
            ba = new BooleanArray();
            dataColumns[col] = ba;
        }
        else {
            ba = (BooleanArray)dataColumns[col];
        }
        ba.put(row, value);
    }
    /** Returns the boolean at the given row, column.
     * @param row the row in the table
     * @param col the column in the table (field num)
     * @return the boolean value in the table
     */
    public boolean getBoolean(int row, int col) {
        BooleanArray ba = (BooleanArray)dataColumns[col];
        return ba.get(row);
    }

    /** Stores a byte value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putByte(int row, int col, byte value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        ByteArray ba = null;
        if (dataColumns[col] == null) {
            ba = new ByteArray();
            dataColumns[col] = ba;
        }
        else {
            ba = (ByteArray)dataColumns[col];
        }
        ba.put(row, value);
    }
    /** Returns the byte at the given row, column.
     * @param row the row in the table
     * @param col the column in the table (field num)
     * @return the byte value in the table
     */
    public byte getByte(int row, int col) {
        ByteArray ba = (ByteArray)dataColumns[col];
        return ba.get(row);
    }

    /** Stores a short value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putShort(int row, int col, short value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        ShortArray sa = null;
        if (dataColumns[col] == null) {
            sa = new ShortArray();
            dataColumns[col] = sa;
        }
        else {
            sa = (ShortArray)dataColumns[col];
        }
        sa.put(row, value);
    }
    /** Returns the short at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the short value.
     */
    public short getShort(int row, int col) {
        ShortArray ba = (ShortArray)dataColumns[col];
        return ba.get(row);
    }

    /** Stores an int value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putInt(int row, int col, int value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        IntArray ia = null;
        if (dataColumns[col] == null) {
            ia = new IntArray();
            dataColumns[col] = ia;
        }
        else {
            ia = (IntArray)dataColumns[col];
        }
        ia.put(row, value);
    }
    /** Returns the int at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public int getInt(int row, int col) {
        IntArray ia = (IntArray)dataColumns[col];
        return ia.get(row);
    }

    /** Stores a long value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putLong(int row, int col, long value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        LongArray la = null;
        if (dataColumns[col] == null) {
            la = new LongArray();
            dataColumns[col] = la;
        }
        else {
            la = (LongArray)dataColumns[col];
        }
        la.put(row, value);
    }
    /** Stores a double value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putDouble(int row, int col, double value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        DoubleArray da = null;
        if (dataColumns[col] == null) {
            da = new DoubleArray();
            dataColumns[col] = da;
        }
        else {
            da = (DoubleArray)dataColumns[col];
        }
        da.put(row, value);
    }
    /** Stores a float value in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putFloat(int row, int col, float value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        FloatArray fa = null;
        if (dataColumns[col] == null) {
            fa = new FloatArray();
            dataColumns[col] = fa;
        }
        else {
            fa = (FloatArray)dataColumns[col];
        }
        fa.put(row, value);
    }



    /** Returns the long at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the long value.
     */
    public long getLong(int row, int col) {
        LongArray ba = (LongArray)dataColumns[col];
        return ba.get(row);
    }
    /** Returns the float at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the float value.
     */
    public float getFloat(int row, int col) {
        FloatArray fa = (FloatArray)dataColumns[col];
        return fa.get(row);
    }
    /** Returns the double at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the double value.
     */
    public double getDouble(int row, int col) {
        DoubleArray da = (DoubleArray)dataColumns[col];
        return da.get(row);
    }

    /** Stores a String in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putString(int row, int col, String value) {
        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        StringArray sa = null;
        if (dataColumns[col] == null) {
            sa = new StringArray();
            dataColumns[col] = sa;
        }
        else {
            sa = (StringArray)dataColumns[col];
        }
        sa.put(row, value);
    }
    /** Stores an Object in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
	public void putObject(int row, int col, Object value) {
        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        ObjectArray oa = null;
        if (dataColumns[col] == null) {
            oa = new ObjectArray();
            dataColumns[col] = oa;
        }
        else {
            oa = (ObjectArray)dataColumns[col];
        }
        oa.put(row, value);
	}

    /** Returns the string at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public String getString(int row, int col) {
        StringArray sa = (StringArray)dataColumns[col];
        return sa.get(row);
    }

    /** Returns the Object at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the Object value.
     */
    public Object getObject(int row, int col) {
        ObjectArray oa = (ObjectArray)dataColumns[col];
        return oa.get(row);
    }

    /** Stores an byte array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putByteArray(int row, int col, byte[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        ByteArrayArray baa = null;
        if (dataColumns[col] == null) {
            baa = new ByteArrayArray();
            dataColumns[col] = baa;
        }
        else {
            baa = (ByteArrayArray)dataColumns[col];
        }
        baa.put(row, value);
    }
    /** Returns the byte array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public byte[] getByteArray(int row, int col) {
        ByteArrayArray baa = (ByteArrayArray)dataColumns[col];
        return baa.get(row);
    }

   /** Stores an short array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putShortArray(int row, int col, short[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        ShortArrayArray saa = null;
        if (dataColumns[col] == null) {
            saa = new ShortArrayArray();
            dataColumns[col] = saa;
        }
        else {
            saa = (ShortArrayArray)dataColumns[col];
        }
        saa.put(row, value);
    }
    /** Returns the short array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public short[] getShortArray(int row, int col) {
        ShortArrayArray saa = (ShortArrayArray)dataColumns[col];
        return saa.get(row);
    }
    /** Stores an int array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putIntArray(int row, int col, int[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        IntArrayArray iaa = null;
        if (dataColumns[col] == null) {
            iaa = new IntArrayArray();
            dataColumns[col] = iaa;
        }
        else {
            iaa = (IntArrayArray)dataColumns[col];
        }
        iaa.put(row, value);
    }
    /** Stores a float array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putFloatArray(int row, int col, float[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        FloatArrayArray faa = null;
        if (dataColumns[col] == null) {
            faa = new FloatArrayArray();
            dataColumns[col] = faa;
        }
        else {
            faa = (FloatArrayArray)dataColumns[col];
        }
        faa.put(row, value);
    }
    /** Stores a double array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putDoubleArray(int row, int col, double[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        DoubleArrayArray daa = null;
        if (dataColumns[col] == null) {
            daa = new DoubleArrayArray();
            dataColumns[col] = daa;
        }
        else {
            daa = (DoubleArrayArray)dataColumns[col];
        }
        daa.put(row, value);
    }






    /** Returns the int array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public int[] getIntArray(int row, int col) {
        IntArrayArray iaa = (IntArrayArray)dataColumns[col];
        return iaa.get(row);
    }

    /** Stores an long array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putLongArray(int row, int col, long[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        LongArrayArray laa = null;
        if (dataColumns[col] == null) {
            laa = new LongArrayArray();
            dataColumns[col] = laa;
        }
        else {
            laa = (LongArrayArray)dataColumns[col];
        }
        laa.put(row, value);
    }
    /** Returns the long array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the long[] value.
     */
    public long[] getLongArray(int row, int col) {
        LongArrayArray laa = (LongArrayArray)dataColumns[col];
        return laa.get(row);
    }

    /** Returns the float array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the float[] value.
     */
    public float[] getFloatArray(int row, int col) {
        FloatArrayArray faa = (FloatArrayArray)dataColumns[col];
        return faa.get(row);
    }

    /** Returns the double array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the int value.
     */
    public double[] getDoubleArray(int row, int col) {
        DoubleArrayArray daa = (DoubleArrayArray)dataColumns[col];
        return daa.get(row);
    }


    /** Stores a String array in the table at the given row
     * and column.  Note - all values in a given column must be
     * of the same type.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @param value The value to store.
     */
    public void putStringArray(int row, int col, String[] value) {

        if (col >= dataColumns.length) {
            growTable(col+1);
        }
        StringArrayArray saa = null;
        if (dataColumns[col] == null) {
            saa = new StringArrayArray();
            dataColumns[col] = saa;
        }
        else {
            saa = (StringArrayArray)dataColumns[col];
        }
        saa.put(row, value);
    }
    /** Returns the String array at the given row, column.
     * @param row The row into the table (specifies which object)
     * @param col The column of the table.  (specifies which field)
     * @return the String[] value.
     */
    public String[] getStringArray(int row, int col) {
        StringArrayArray saa = (StringArrayArray)dataColumns[col];
        return saa.get(row);
    }




    /** increases the number of columns in the table
     * @param numCols The number of columns needed in the table
     */
    private void growTable(int numCols) {
        Array[] newCols = new Array[numCols];
        System.arraycopy(dataColumns,0,newCols,0,dataColumns.length);
        dataColumns = newCols;
    }


}

