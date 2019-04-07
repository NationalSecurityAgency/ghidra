/* ###
 * IP: Public Domain
 */
package mobiledevices.dmg.ghidra;

import java.io.IOException;

/**
 * A class for reading data from a 
 * generic byte provider in either big-endian or little-endian.
 * 
 * 
 */
public class GBinaryReader {
    /**
     * The size of a BYTE in Java.
     */
    public final static int SIZEOF_BYTE = 1;
    /**
     * The size of a SHORT in Java.
     */
    public final static int SIZEOF_SHORT = 2;
    /**
     * The size of an INTEGER in Java.
     */
    public final static int SIZEOF_INT = 4;
    /**
     * The size of a LONG in Java.
     */
    public final static int SIZEOF_LONG = 8;

    private GByteProvider provider;
    private GDataConverter converter;
    private long currentIndex;

    /**
     * Constructs a reader using the given 
     * file and endian-order.
     * 
     * If isLittleEndian is true, then all values read
     * from the file will be done so assuming
     * little-endian order.
     * 
     * Otherwise, if isLittleEndian
     * is false, then all values will be read
     * assuming big-endian order.
     * 
     * @param provider the byte provider
     * @param isLittleEndian the endian-order
     */
    public GBinaryReader(GByteProvider provider, boolean isLittleEndian) {
        this.provider = provider;
        setLittleEndian(isLittleEndian);
    }

    /**
     * Returns a clone of this reader positioned at the new index.
     * @param newIndex the new index
     * @return a clone of this reader positioned at the new index
     */
    public GBinaryReader clone(int newIndex) {
    	GBinaryReader clone = new GBinaryReader(provider, isLittleEndian());
    	clone.converter = converter;
    	clone.currentIndex = newIndex;
    	return clone;
    }

    /**
     * Returns true if this reader will extract values in little endian,
     * otherwise in big endian.
     * @return true is little endian, false is big endian
     */
	public boolean isLittleEndian() {
		return converter instanceof GDataConverterLE;
	}

	/**
	 * Sets the endian of this binary reader.
	 * @param isLittleEndian true for little-endian and false for big-endian
	 */
	public void setLittleEndian(boolean isLittleEndian) {
        if (isLittleEndian) {
            converter = new GDataConverterLE();
        }
        else {
            converter = new GDataConverterBE();
        }
	}

    /**
     * Returns the length of the underlying file.
     * @return returns the length of the underlying file
     * @exception IOException if an I/O error occurs
     */
    public long length() throws IOException {
        return provider.length();
    }

    /**
     * Returns true if the specified index into 
     * the underlying byte provider is valid.
     * @param index the index in the byte provider
     * @return returns true if the specified index is valid
     * @exception IOException if an I/O error occurs
     */
    public boolean isValidIndex(int index) throws IOException {
        return provider.isValidIndex(index & GConv.INT_MASK);
    }

    /**
     * Returns true if the specified index into 
     * the underlying byte provider is valid.
     * @param index the index in the byte provider
     * @return returns true if the specified index is valid
     * @exception IOException if an I/O error occurs
     */
    public boolean isValidIndex(long index) throws IOException {
        return provider.isValidIndex(index);
    }

    /**
     * Aligns the current index on the specified alignment value.
     * For example, if current index was 123 and align value was
     * 16, then current index would become 128.
     * @param alignValue
     * @return the number of bytes required to align
     */
    public int align(int alignValue) {
        long align = currentIndex % alignValue;
        if (align == 0) {
            return 0;
        }
        currentIndex = currentIndex + (alignValue - align);
        return (int)(alignValue - align);
    }

    ////////////////////////////////////////////////////////////////////

    /**
     * A convenience method for setting the index using
     * an integer.
     */
    public void setPointerIndex(int index) {
        this.currentIndex = index & GConv.INT_MASK;
    }

    /**
     * Sets the current index to the specified value.
     * The pointer index will allow the reader
     * to operate as a psuedo-iterator.
     * 
     * @param index the byte provider index value
     */
    public void setPointerIndex(long index) {
        this.currentIndex = index;
    }

    /**
     * Returns the current index value.
     * @return the current index value
     */
    public long getPointerIndex() {
        return currentIndex;
    }

    /**
     * Peeks at the next byte without incrementing
     * the current index.
     * @return the next byte
     * @exception IOException if an I/O error occurs
     */
    public byte peekNextByte() throws IOException {
        return readByte(currentIndex);
    }

    /**
     * Peeks at the next short without incrementing
     * the current index.
     * @return the next short
     * @exception IOException if an I/O error occurs
     */
    public short peekNextShort() throws IOException {
        return readShort(currentIndex);
    }

    /**
     * Peeks at the next integer without incrementing
     * the current index.
     * @return the next int
     * @exception IOException if an I/O error occurs
     */
    public int peekNextInt() throws IOException {
        return readInt(currentIndex);
    }

    /**
     * Peeks at the next long without incrementing
     * the current index.
     * @return the next long
     * @exception IOException if an I/O error occurs
     */
    public long peekNextLong() throws IOException {
        return readLong(currentIndex);
    }

    /**
     * Reads the byte at the current index and then increments the current
     * index by <code>SIZEOF_BYTE</code>.
     * @return the byte at the current index
     * @exception IOException if an I/O error occurs
     */
    public byte readNextByte() throws IOException {
        byte b = readByte(currentIndex);
        currentIndex += SIZEOF_BYTE;
        return b;
    }

    /**
     * Reads the byte at the current index and then increments the current
     * index by <code>SIZEOF_BYTE</code>.
     * @return the byte at the current index
     * @exception IOException if an I/O error occurs
     */
    public byte readNextByte(byte minClamp, byte maxClamp, Byte... exceptions) throws IOException {
        byte b = readByte(currentIndex, minClamp, maxClamp, exceptions);
        currentIndex += SIZEOF_BYTE;
        return b;
    }

    /**
     * Reads the short at the current index and then increments the current
     * index by <code>SIZEOF_SHORT</code>.
     * @return the short at the current index
     * @exception IOException if an I/O error occurs
     */
    public short readNextShort() throws IOException {
        short s = readShort(currentIndex);
        currentIndex+=SIZEOF_SHORT;
        return s;
    }

    /**
     * Reads the short at the current index and then increments the current
     * index by <code>SIZEOF_SHORT</code>.
     * @return the short at the current index
     * @exception IOException if an I/O error occurs
     */
    public short readNextShort(short minClamp, short maxClamp, Short... exceptions) throws IOException {
        short s = readShort(currentIndex, minClamp, maxClamp, exceptions);
        currentIndex+=SIZEOF_SHORT;
        return s;
    }

    /**
     * Reads the integer at the current index and then increments the current
     * index by <code>SIZEOF_INT</code>.
     * @return the integer at the current index
     * @exception IOException if an I/O error occurs
     */
    public int readNextInt() throws IOException {
        int i = readInt(currentIndex);
        currentIndex+=SIZEOF_INT;
        return i;
    }

    /**
     * Reads the integer at the current index and then increments the current
     * index by <code>SIZEOF_INT</code>.
     * @return the integer at the current index
     * @exception IOException if an I/O error occurs
     */
    public int readNextInt(int minClamp, int maxClamp, Integer... exceptions) throws IOException {
        int i = readInt(currentIndex, minClamp, maxClamp, exceptions);
        currentIndex+=SIZEOF_INT;
        return i;
    }

    /**
     * Reads the long at the current index and then increments the current
     * index by <code>SIZEOF_LONG</code>.
     * @return the long at the current index
     * @exception IOException if an I/O error occurs
     */
    public long readNextLong() throws IOException {
        long l = readLong(currentIndex);
        currentIndex+=SIZEOF_LONG;
        return l;
    }

    /**
     * Reads the long at the current index and then increments the current
     * index by <code>SIZEOF_LONG</code>.
     * @return the long at the current index
     * @exception IOException if an I/O error occurs
     */
    public long readNextLong(long minClamp, long maxClamp, Long... exceptions) throws IOException {
        long l = readLong(currentIndex, minClamp, maxClamp, exceptions);
        currentIndex+=SIZEOF_LONG;
        return l;
    }

    /**
     * Reads the Ascii string at the current index and then increments the current
     * index by the length of the Ascii string that was found. This method
     * expects the string to be null-terminated.
     * @return the null-terminated Ascii string at the current index
     * @exception IOException if an I/O error occurs
     */
    public String readNextAsciiString() throws IOException {
        String s = readAsciiString(currentIndex);
        currentIndex+=(s.length()+1);
        return s;
    }

    /**
     * Reads an Ascii string of <code>length</code>
     * characters starting at the current index and then increments the current
     * index by <code>length</code>.
     * 
     * @return the Ascii string at the current index
     */
    public String readNextAsciiString(int length) throws IOException {
        String s = readAsciiString(currentIndex, length);
        currentIndex+=length;
        return s;
    }

    /**
     * Reads the Unicode string at the current index and then increments the current
     * index by the length of the Unicode string that was found. This method
     * expects the string to be double null-terminated ('\0\0').
     * @return the null-terminated Ascii string at the current index
     * @exception IOException if an I/O error occurs
     */
    public String readNextUnicodeString() throws IOException {
        String s = readUnicodeString(currentIndex);
        currentIndex += ((s.length()+1)*2);
        return s;
    }

    /**
     * Reads the unicode string at the current index and then increments the current
     * index by <code>length</code>.
     * @return the unicode string at the current index
     * @exception IOException if an I/O error occurs
     */
    public String readNextUnicodeString(int length) throws IOException {
        String s = readUnicodeString(currentIndex, length);
        currentIndex+=(length*2);
        return s;
    }

    /**
     * Reads a byte array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_BYTE * nElements</code>.
     * @return the byte array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public byte [] readNextByteArray(int nElements) throws IOException {
        byte [] b = readByteArray(currentIndex, nElements);
        currentIndex+=(SIZEOF_BYTE*nElements);
        return b;
    }

    /**
     * Reads a byte array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_BYTE * nElements</code>.
     * @return the byte array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public byte [] readNextByteArray(int nElements, byte minClamp, byte maxClamp, Byte... exceptions) throws IOException {
        byte [] b = readByteArray(currentIndex, nElements, minClamp, maxClamp, exceptions);
        currentIndex+=(SIZEOF_BYTE*nElements);
        return b;
    }

    /**
     * Reads a short array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_SHORT * nElements</code>.
     * @return the short array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public short [] readNextShortArray(int nElements) throws IOException {
        short [] s = readShortArray(currentIndex, nElements);
        currentIndex+=(SIZEOF_SHORT*nElements);
        return s;
    }

    /**
     * Reads a short array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_SHORT * nElements</code>.
     * @return the short array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public short [] readNextShortArray(int nElements, short minClamp, short maxClamp, Short... exceptions) throws IOException {
        short [] s = readShortArray(currentIndex, nElements, minClamp, maxClamp, exceptions);
        currentIndex+=(SIZEOF_SHORT*nElements);
        return s;
    }

    /**
     * Reads an integer array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_INT * nElements</code>.
     * @return the integer array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public int [] readNextIntArray(int nElements) throws IOException {
        int [] i = readIntArray(currentIndex, nElements);
        currentIndex+=(SIZEOF_INT*nElements);
        return i;
    }

    /**
     * Reads an integer array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_INT * nElements</code>.
     * @return the integer array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public int [] readNextIntArray(int nElements, int minClamp, int maxClamp, Integer... exceptions) throws IOException {
        int [] i = readIntArray(currentIndex, nElements, minClamp, maxClamp, exceptions);
        currentIndex+=(SIZEOF_INT*nElements);
        return i;
    }

    /**
     * Reads a long array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_LONG * nElements</code>.
     * @return the long array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public long [] readNextLongArray(int nElements) throws IOException {
        long [] l = readLongArray(currentIndex, nElements);
        currentIndex+=(SIZEOF_LONG*nElements);
        return l;
    }

    /**
     * Reads a long array of <code>nElements</code>
     * starting at the current index and then increments the current
     * index by <code>SIZEOF_LONG * nElements</code>.
     * @return the long array starting at the current index
     * @exception IOException if an I/O error occurs
     */
    public long [] readNextLongArray(int nElements, long minClamp, long maxClamp, Long... exceptions) throws IOException {
        long [] l = readLongArray(currentIndex, nElements, minClamp, maxClamp, exceptions);
        currentIndex+=(SIZEOF_LONG*nElements);
        return l;
    }

    ////////////////////////////////////////////////////////////////////

    /**
     * Returns a null-terminated Ascii string starting
     * at <code>index</code>. The end of the string
     * is denoted by a <code>null</code> character.
     * 
     * @param index the index where the Ascii string begins
     * @return the Ascii string
     * @exception IOException if an I/O error occurs
     */
    public String readAsciiString(long index) throws IOException {
        StringBuffer buffer = new StringBuffer();
        while (true) {
            byte b = provider.readByte(index++);
            if ((b >= 32) && (b <= 126)) {
                buffer.append((char)b);
            }
            else {
                break;
            }
        }
        return buffer.toString().trim();
    }

    /**
     * Returns an Ascii string of <code>length</code> bytes
     * starting at <code>index</code>. This method does not
     * care about null-terminators.
     * @param index the index where the Ascii string begins
     * @param length the length of the Ascii string
     * @return the Ascii string
     * @exception IOException if an I/O error occurs
     */
    public String readAsciiString(long index, int length) throws IOException {
        StringBuffer buffer = new StringBuffer();
        for (int i = 0 ; i < length ; ++i) {
            byte b = provider.readByte(index++);
            buffer.append((char) (b & 0x00FF));
        }
        return buffer.toString().trim();
    }

    /**
     * Returns a null-terminated Unicode string starting
     * at <code>index</code>. The end of the string
     * is denoted by two-byte Unicode <code>null</code> character.
     * @param index the index where the Unicode string begins
     * @return the Unicode string
     * @exception IOException if an I/O error occurs
     */
    public String readUnicodeString(long index) throws IOException {
        StringBuffer buffer = new StringBuffer();
		char c = 0;
		int i = 0;
        while (i < length()) {
            c  = (char)((provider.readByte(index++) & 0xff));
            c += (char)((provider.readByte(index++) & 0xff) << 8);
            if (c == 0x0000) {
                break;
            }
            buffer.append(c); 
            i += 2;
        }
        return buffer.toString().trim();
    }

    /**
     * Returns a Unicode string of <code>length</code> bytes
     * starting at <code>index</code>. This method does not
     * care about null-terminators.
     * @param index the index where the Unicode string begins
     * @param length the length of the Unicode string
     * @return the Unicode string
     * @exception IOException if an I/O error occurs
     */
    public String readUnicodeString(long index, int length) throws IOException {
        StringBuffer buffer = new StringBuffer();
        char c = 0;
        for (int i = 0 ; i < length*2 ; i+=2) {
            c  = (char)((provider.readByte(index++) & 0xff));
            c += (char)((provider.readByte(index++) & 0xff) << 8);
            buffer.append(c);
        }
        return buffer.toString().trim();
    }

    /**
     * Returns the BYTE at <code>index<code>.
     * @param index the index where the BYTE begins
     * @return the BYTE
     * @exception IOException if an I/O error occurs
     */
    public byte readByte(long index) throws IOException {
        return provider.readByte(index);
    }

    /**
     * Returns the BYTE at <code>index</code>.
     * @param index the index where the BYTE begins
     * @return the BYTE
     * @exception IOException if an I/O error occurs
     */
    public byte readByte(long index, byte minClamp, byte maxClamp, Byte... exceptions) throws IOException {
        byte b = readByte(index);
        return clampByte(b, minClamp, maxClamp, exceptions);
    }

    /**
     * Returns the SHORT at <code>index</code>.
     * @param index the index where the SHORT begins
     * @return the SHORT
     * @exception IOException if an I/O error occurs
     */
    public short readShort(long index) throws IOException {
        byte [] bytes = provider.readBytes(index, SIZEOF_SHORT);
        return converter.getShort(bytes);
    }

    /**
     * Returns the SHORT at <code>index</code>.
     * @param index the index where the SHORT begins
     * @return the SHORT
     * @exception IOException if an I/O error occurs
     */
    public short readShort(long index, short minClamp, short maxClamp, Short... exceptions) throws IOException {
        short s = readShort(index);
        return clampShort(s, minClamp, maxClamp, exceptions);
    }

    /**
     * Returns the INTEGER at <code>index</code>.
     * @param index the index where the INTEGER begins
     * @return the INTEGER
     * @exception IOException if an I/O error occurs
     */
    public int readInt(long index) throws IOException {
        byte [] bytes = provider.readBytes(index, SIZEOF_INT);
        return converter.getInt(bytes);
    }

    /**
     * Returns the INTEGER at <code>index</code>.
     * @param index the index where the INTEGER begins
     * @return the INTEGER
     * @exception IOException if an I/O error occurs
     */
    public int readInt(long index, int minClamp, int maxClamp, Integer... exceptions) throws IOException {
        int i = readInt(index);
        return clampInt(i, minClamp, maxClamp, exceptions);
    }

    /**
     * Returns the LONG at <code>index</code>.
     * @param index the index where the LONG begins
     * @return the LONG
     * @exception IOException if an I/O error occurs
     */
    public long readLong(long index) throws IOException {
        byte [] bytes = provider.readBytes(index, SIZEOF_LONG);
        return converter.getLong(bytes);
    }

    /**
     * Returns the LONG at <code>index</code>.
     * @param index the index where the LONG begins
     * @return the LONG
     * @exception IOException if an I/O error occurs
     */
    public long readLong(long index, long minClamp, long maxClamp, Long... exceptions) throws IOException {
        long l = readLong(index);
        return clampLong(l, minClamp, maxClamp, exceptions);
    }

    /**
     * Returns the BYTE array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the BYTE begins
     * @param nElements the number of array elements
     * @return the BYTE array
     * @exception IOException if an I/O error occurs
     */
    public byte [] readByteArray(long index, int nElements) throws IOException {
        if (nElements < 0) {
            throw new IOException("Invalid number of elements specified: "+nElements);
        }
        return provider.readBytes(index, nElements);
    }

    /**
     * Returns the BYTE array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the BYTE begins
     * @param nElements the number of array elements
     * @return the BYTE array
     * @exception IOException if an I/O error occurs
     */
    public byte [] readByteArray(long index, int nElements, byte minClamp, byte maxClamp, Byte... exceptions) throws IOException {
        byte[] array = readByteArray(index, nElements);
        for (int ii = 0; ii < array.length; ++ii) {
            array[ii] = clampByte(array[ii], minClamp, maxClamp, exceptions);
        }
        return array;
    }

    /**
     * Returns the SHORT array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the SHORT begins
     * @param nElements the number of array elements
     * @return the SHORT array
     * @exception IOException if an I/O error occurs
     */
    public short [] readShortArray(long index, int nElements) throws IOException {
        if (nElements < 0) {
            throw new IOException("Invalid number of elements specified: "+nElements);
        }
        short [] arr = new short[nElements];
        for (int i = 0 ; i < nElements ; ++i) {
            arr[i] = readShort(index);
            index += SIZEOF_SHORT;
        }
        return arr;
    }

    /**
     * Returns the SHORT array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the SHORT begins
     * @param nElements the number of array elements
     * @return the SHORT array
     * @exception IOException if an I/O error occurs
     */
    public short [] readShortArray(long index, int nElements, short minClamp, short maxClamp, Short... exceptions) throws IOException {
        short[] array = readShortArray(index, nElements);
        for (int ii = 0; ii < array.length; ++ii) {
            array[ii] = clampShort(array[ii], minClamp, maxClamp, exceptions);
        }
        return array;
    }

    /**
     * Returns the INTEGER array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the INTEGER begins
     * @param nElements the number of array elements
     * @return the INTEGER array
     * @exception IOException if an I/O error occurs
     */
    public int [] readIntArray(long index, int nElements) throws IOException {
        if (nElements < 0) {
            throw new IOException("Invalid number of elements specified: "+nElements);
        }
        int [] arr = new int[nElements];
        for (int i = 0 ; i < nElements ; ++i) {
            arr[i] = readInt(index);
            index += SIZEOF_INT;
        }
        return arr;
    }

    /**
     * Returns the INTEGER array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the INTEGER begins
     * @param nElements the number of array elements
     * @return the INTEGER array
     * @exception IOException if an I/O error occurs
     */
    public int [] readIntArray(long index, int nElements, int minClamp, int maxClamp, Integer... exceptions) throws IOException {
        int[] array = readIntArray(index, nElements);
        for (int ii = 0; ii < array.length; ++ii) {
            array[ii] = clampInt(array[ii], minClamp, maxClamp, exceptions);
        }
        return array;
    }

    /**
     * Returns the LONG array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the LONG begins
     * @param nElements the number of array elements
     * @return the LONG array
     * @exception IOException if an I/O error occurs
     */
    public long [] readLongArray(long index, int nElements) throws IOException {
        if (nElements < 0) {
            throw new IOException("Invalid number of elements specified: "+nElements);
        }
        long [] arr = new long[nElements];
        for (int i = 0 ; i < nElements ; ++i) {
            arr[i] = readLong(index);
            index += SIZEOF_LONG;
        }
        return arr;
    }

    /**
     * Returns the LONG array of <code>nElements</code>
     * starting at <code>index</code>.
     * @param index the index where the LONG begins
     * @param nElements the number of array elements
     * @return the LONG array
     * @exception IOException if an I/O error occurs
     */
    public long [] readLongArray(long index, int nElements, long minClamp, long maxClamp, Long... exceptions) throws IOException {
        long[] array = readLongArray(index, nElements);
        for (int ii = 0; ii < array.length; ++ii) {
            array[ii] = clampLong(array[ii], minClamp, maxClamp, exceptions);
        }
        return array;
    }

    /**
     * Returns the Ascii string array of <code>nElements</code>
     * starting at <code>index</code>
     * @param index the index where the Ascii Strings begin
     * @param nElements the number of array elements
     * @return the Ascii String array
     * @exception IOException if an I/O error occurs
     */
    public String [] readAsciiStringArray(long index, int nElements) throws IOException {
        if (nElements < 0) {
            throw new IOException("Invalid number of elements specified: "+nElements);
        }
        String [] arr = new String[nElements];
        for (int i = 0 ; i < nElements ; ++i) {
            String tmp = readAsciiString(index);
            arr[i] = tmp;
            index += (tmp == null ? 1 : tmp.length());
        }
        return arr;
    }

    /**
     * Writes the specified byte at the specified index.
     * @param index the index where the byte should be written
     * @param value the byte value to be written
     * @exception IOException if an I/O error occurs
     */
    public void writeByte(long index, byte value) throws IOException {
        provider.writeByte(index, value);
    }

    /**
     * Writes the specified short at the specified index.
     * @param index the index where the short should be written
     * @param value the short value to be written
     * @exception IOException if an I/O error occurs
     */
    public void writeShort(long index, short value) throws IOException {
        byte [] bytes = converter.getBytes(value);
        provider.writeBytes(index, bytes);
    }

    /**
     * Writes the specified int at the specified index.
     * @param index the index where the int should be written
     * @param value the int value to be written
     * @exception IOException if an I/O error occurs
     */
    public void writeInt(long index, int value) throws IOException {
        byte [] bytes = converter.getBytes(value);
        provider.writeBytes(index, bytes);
    }

    /**
     * Writes the specified long at the specified index.
     * @param index the index where the long should be written
     * @param value the long value to be written
     * @exception IOException if an I/O error occurs
     */
    public void writeLong(long index, long value) throws IOException {
        byte [] bytes = converter.getBytes(value);
        provider.writeBytes(index, bytes);
    }

    /**
     * Returns the underlying byte provider.
     * @return the underlying byte provider
     */
    public GByteProvider getByteProvider() {
        return provider;
    }

    protected byte clampByte(byte b, byte minClamp, byte maxClamp, Byte... exceptions) {
        if (maxClamp < minClamp) {
            throw new IllegalArgumentException("maxClamp < minClamp not allowed");
        }
        if (exceptions != null) {
            if (exceptions.length % 2 != 0) {
                throw new IllegalArgumentException("exceptions must be pairs of (flag, replacement) bytes");
            }
        }
        boolean clamp = true;
        if (exceptions != null) {
            for (int ii = 0; ii < exceptions.length; ii += 2) {
                if (b == exceptions[ii]) {
                    b = exceptions[ii+1];
                    clamp = false;
                    break;
                }
            }
        }
        if (clamp) {
            if (b < minClamp) {
                b = minClamp;
            } else if (b > maxClamp) {
                b = maxClamp;
            }
        }
        return b;
    }

    protected short clampShort(short s, short minClamp, short maxClamp, Short... exceptions) {
        if (maxClamp < minClamp) {
            throw new IllegalArgumentException("maxClamp < minClamp not allowed");
        }
        if (exceptions != null) {
            if (exceptions.length % 2 != 0) {
                throw new IllegalArgumentException("exceptions must be pairs of (flag, replacement) shorts");
            }
        }
        boolean clamp = true;
        if (exceptions != null) {
            for (int ii = 0; ii < exceptions.length; ii += 2) {
                if (s == exceptions[ii]) {
                    s = exceptions[ii+1];
                    clamp = false;
                    break;
                }
            }
        }
        if (clamp) {
            if (s < minClamp) {
                s = minClamp;
            } else if (s > maxClamp) {
                s = maxClamp;
            }
        }
        return s;
    }

    protected int clampInt(int i, int minClamp, int maxClamp, Integer... exceptions) {
        if (maxClamp < minClamp) {
            throw new IllegalArgumentException("maxClamp < minClamp not allowed");
        }
        if (exceptions != null) {
            if (exceptions.length % 2 != 0) {
                throw new IllegalArgumentException("exceptions must be pairs of (flag, replacement) ints");
            }
        }
        boolean clamp = true;
        if (exceptions != null) {
            for (int ii = 0; ii < exceptions.length; ii += 2) {
                if (i == exceptions[ii]) {
                    i = exceptions[ii+1];
                    clamp = false;
                    break;
                }
            }
        }
        if (clamp) {
            if (i < minClamp) {
                i = minClamp;
            } else if (i > maxClamp) {
                i = maxClamp;
            }
        }
        return i;
    }

    protected long clampLong(long l, long minClamp, long maxClamp, Long... exceptions) {
        if (maxClamp < minClamp) {
            throw new IllegalArgumentException("maxClamp < minClamp not allowed");
        }
        if (exceptions != null) {
            if (exceptions.length % 2 != 0) {
                throw new IllegalArgumentException("exceptions must be pairs of (flag, replacement) longs");
            }
        }
        boolean clamp = true;
        if (exceptions != null) {
            for (int ii = 0; ii < exceptions.length; ii += 2) {
                if (l == exceptions[ii]) {
                    l = exceptions[ii+1];
                    clamp = false;
                    break;
                }
            }
        }
        if (clamp) {
            if (l < minClamp) {
                l = minClamp;
            } else if (l > maxClamp) {
                l = maxClamp;
            }
        }
        return l;
    }
}
