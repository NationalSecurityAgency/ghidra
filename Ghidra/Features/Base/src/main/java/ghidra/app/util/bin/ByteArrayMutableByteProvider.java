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
package ghidra.app.util.bin;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;

/**
 * An implementation of ByteProvider where the underlying bytes are held in-
 * memory with a byte buffer. The buffer grows automatically as needed to fit
 * written data.
 */
public class ByteArrayMutableByteProvider implements MutableByteProvider {
    private byte[] data;

    private void ensureCapacity(int newCapacity) {
        if (data.length < newCapacity) {
            data = Arrays.copyOf(data, newCapacity);
        }
    }

    /**
     * Create an empty ByteArrayMutableByteProvider.
     */
    public ByteArrayMutableByteProvider() {
        data = new byte[0];
    }

    /**
     * Create a ByteArrayMutableByteProvider initialized with the given array
     * @param bytes Initial content of the ByteArrayMutableByteProvider.
     */
    public ByteArrayMutableByteProvider(byte[] bytes) {
        data = Arrays.copyOf(bytes, bytes.length);
    }

    @Override
    public File getFile() {
        return null;
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public String getAbsolutePath() {
        return null;
    }

    @Override
    public long length() throws IOException {
        return data.length;
    }

    @Override
    public boolean isValidIndex(long index) {
        return index < data.length;
    }

    @Override
    public void close() throws IOException {
    }

    @Override
    public byte readByte(long index) throws IOException {
        try {
            return data[(int) index];
        }
        catch (IndexOutOfBoundsException e) {
            throw new IOException(e);
        }
    }

    @Override
    public byte[] readBytes(long index, long length) throws IOException {
        try {
            return Arrays.copyOfRange(data, (int) index, (int) (index + length));
        }
        catch (IndexOutOfBoundsException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void writeByte(long index, byte value) throws IOException {
        ensureCapacity((int) (index + 1));
        data[(int) index] = value;
    }

    @Override
    public void writeBytes(long index, byte[] values) throws IOException {
        ensureCapacity((int) (index + values.length));
        System.arraycopy(values, 0, data, (int) index, values.length);
    }
}
