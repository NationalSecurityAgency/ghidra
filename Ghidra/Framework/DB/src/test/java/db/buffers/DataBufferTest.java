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
package db.buffers;

import static org.junit.Assert.assertEquals;

import java.io.*;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class DataBufferTest extends AbstractGenericTest {

	Random random = new Random();

	private byte[] buffer = new byte[16 * 1024];

	public DataBufferTest() {
		super();
	}

	private void transferData(boolean useRandomFill) throws Exception {

		for (int k = 0; k < 20; k++) {

			if (useRandomFill) {
				random.nextBytes(buffer);
			}
			else {
				Arrays.fill(buffer, (byte) 0xff);
			}

			for (int i = 0; i < 16; i++) {

				// Progressively zero-out regions within buffer
				// to permit increasingly more compression
				if (i != 0) {
					int nextZeroIndex = i * 1000;
					for (int n = 0; n < 1000; n++) {
						buffer[nextZeroIndex++] = 0;
					}
				}

				DataBuffer dataBuf = new DataBuffer(buffer);
				dataBuf.setDirty(true);

				MyObjectOutput outData = new MyObjectOutput();
				dataBuf.writeExternal(outData);

				MyObjectInput inData = new MyObjectInput(outData);
				DataBuffer inDataBuf = new DataBuffer();
				inDataBuf.readExternal(inData);

				assertEquals(0, inData.available());

				assertEquals(dataBuf.isDirty(), inDataBuf.isDirty());
				assertEquals(dataBuf.length(), inDataBuf.length());

				int len = dataBuf.length();
				for (int n = 0; n < len; n++) {
					assertEquals("Bytes differ at offset " + n, dataBuf.getByte(n),
						inDataBuf.getByte(n));
				}

			}
		}
	}

	@Test
	public void testCompressedInOut() throws Exception {
		DataBuffer.enableCompressedSerializationOutput(true);
		transferData(true);
		transferData(false);
	}

	@Test
	public void testUncompressedInOut() throws Exception {
		DataBuffer.enableCompressedSerializationOutput(false);
		transferData(true);
		transferData(false);
	}

	private class MyObjectInput implements ObjectInput {

		private final int serialDataLen;
		private int serialDataPosition;
		private byte[] serialData;

		MyObjectInput(MyObjectOutput out) {
			this.serialData = out.serialData;
			this.serialDataLen = out.serialDataLen;
		}

		@Override
		public void readFully(byte[] b) throws IOException {
			readFully(b, 0, b.length);
		}

		@Override
		public void readFully(byte[] b, int off, int len) throws IOException {
			int index = off;
			for (int i = 0; i < len; i++) {
				if (serialDataPosition >= serialDataLen) {
					throw new EOFException();
				}
				b[index++] = serialData[serialDataPosition++];
			}
		}

		@Override
		public int skipBytes(int n) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean readBoolean() throws IOException {
			byte b = readByte();
			if (b == 0)
				return false;
			if (b == 1)
				return true;
			throw new IOException("Invalid boolean value: " + b);
		}

		@Override
		public byte readByte() throws IOException {
			if (serialDataPosition >= serialDataLen) {
				throw new EOFException();
			}
			return serialData[serialDataPosition++];
		}

		@Override
		public int readUnsignedByte() throws IOException {
			if (serialDataPosition >= serialDataLen) {
				throw new EOFException();
			}
			return serialData[serialDataPosition++] & 0xff;
		}

		@Override
		public short readShort() throws IOException {
			int val;
			val = readUnsignedByte();
			val = val | (readUnsignedByte() << 8);
			return (short) val;
		}

		@Override
		public int readUnsignedShort() throws IOException {
			return readShort() & 0xffff;
		}

		@Override
		public char readChar() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public int readInt() throws IOException {
			int val;
			val = readUnsignedByte();
			val = val | (readUnsignedByte() << 8);
			val = val | (readUnsignedByte() << 16);
			val = val | (readUnsignedByte() << 24);
			return val;
		}

		@Override
		public long readLong() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public float readFloat() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public double readDouble() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public String readLine() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public String readUTF() throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public Object readObject() throws ClassNotFoundException, IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public int read() throws IOException {
			if (serialDataPosition >= serialDataLen) {
				return -1;
			}
			return serialData[serialDataPosition++] & 0xff;
		}

		@Override
		public int read(byte[] bytes) throws IOException {
			return read(bytes, 0, bytes.length);
		}

		@Override
		public int read(byte[] bytes, int off, int len) throws IOException {
			int index = off;
			for (int i = 0; i < len; i++) {
				int b = read();
				if (b < 0) {
					return i == 0 ? -1 : i;
				}
				bytes[index++] = (byte) b;
			}
			return len;
		}

		@Override
		public long skip(long n) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public int available() throws IOException {
			return Math.max(0, serialDataLen - serialDataPosition);
		}

		@Override
		public void close() throws IOException {
			serialDataPosition = serialDataLen;
		}

	}

	private class MyObjectOutput implements ObjectOutput {

		private int serialDataLen;
		private byte[] serialData = new byte[2 * buffer.length];

		MyObjectOutput() {
			serialDataLen = 0;
		}

		@Override
		public void writeBoolean(boolean v) throws IOException {
			serialData[serialDataLen++] = (byte) (v ? 1 : 0);
		}

		@Override
		public void writeByte(int v) throws IOException {
			serialData[serialDataLen++] = (byte) v;
		}

		@Override
		public void writeShort(int v) throws IOException {
			writeByte(v);
			writeByte(v >> 8);
		}

		@Override
		public void writeChar(int v) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeInt(int v) throws IOException {
			writeByte(v);
			writeByte(v >> 8);
			writeByte(v >> 16);
			writeByte(v >> 24);
		}

		@Override
		public void writeLong(long v) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeFloat(float v) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeDouble(double v) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeBytes(String s) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeChars(String s) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeUTF(String s) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void writeObject(Object obj) throws IOException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void write(int b) throws IOException {
			serialData[serialDataLen++] = (byte) b;
		}

		@Override
		public void write(byte[] b) throws IOException {
			write(b, 0, b.length);
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			int index = off;
			for (int i = 0; i < len; i++) {
				serialData[serialDataLen++] = b[index++];
			}
		}

		@Override
		public void flush() throws IOException {
			// do nothing
		}

		@Override
		public void close() throws IOException {
			// do nothing
		}

	}

}
