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
package ghidra.util;

import java.io.*;

/**
 * Implementation for ObjectStorage to save and restore Strings and
 * Java primitives using an ObjectOutputStream and ObjectInputStream,
 * respectively.
 * 
 * 
 */
public class ObjectStorageStreamAdapter implements ObjectStorage {
	ObjectOutputStream out;
	ObjectInputStream in;
    /**
     * Constructor for ObjectStorageStreamAdapter.
     * @param out output stream to write to
     */
    public ObjectStorageStreamAdapter(ObjectOutputStream out) {
    	this.out = out;
    }
    /**
     * Constructor for new ObjectStorageStreamAdapter
     * @param in input stream to read from
     */
    public ObjectStorageStreamAdapter(ObjectInputStream in) {
    	this.in = in;
    }

    /**
     * @see ghidra.util.ObjectStorage#putInt(int)
     */
    public void putInt(int value) {
        try {
            out.writeInt(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putByte(byte)
     */
    public void putByte(byte value) {
        try {
            out.writeByte(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putShort(short)
     */
    public void putShort(short value) {
        try {
            out.writeShort(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putLong(long)
     */
    public void putLong(long value) {
        try {
            out.writeLong(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putString(String)
     */
    public void putString(String value) {
        try {
            out.writeObject(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putBoolean(boolean)
     */
    public void putBoolean(boolean value) {
        try {
            out.writeBoolean(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putFloat(float)
     */
    public void putFloat(float value) {
        try {
            out.writeFloat(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putDouble(double)
     */
    public void putDouble(double value) {
        try {
            out.writeDouble(value);
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#getInt()
     */
    public int getInt() {
        try {
            return in.readInt();
        } catch (IOException e) {
        	return 0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getByte()
     */
    public byte getByte() {
        try {
            return in.readByte();
        } catch (IOException e) {
        	return (byte)0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getShort()
     */
    public short getShort() {
        try {
            return in.readShort();
        } catch (IOException e) {
        	return (short)0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getLong()
     */
    public long getLong() {
        try {
            return in.readLong();
        } catch (IOException e) {
        	return 0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getBoolean()
     */
    public boolean getBoolean() {
        try {
            return in.readBoolean();
        } catch (IOException e) {
        	return false;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getString()
     */
    public String getString() {
        try {
	        return (String)in.readObject();
        }catch(Exception e) {
        	return null;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getFloat()
     */
    public float getFloat() {
        try {
            return in.readFloat();
        } catch (IOException e) {
        	return 0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getDouble()
     */
    public double getDouble() {
        try {
            return in.readDouble();
        } catch (IOException e) {
        	return 0.0;
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#putInts(int[])
     */
    public void putInts(int[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeInt(value[i]);
            }
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putBytes(byte[])
     */
    public void putBytes(byte[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeByte(value[i]);
            }
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putShorts(short[])
     */
    public void putShorts(short[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeShort(value[i]);
            }
        } catch (IOException e) {}

    }

    /**
     * @see ghidra.util.ObjectStorage#putLongs(long[])
     */
    public void putLongs(long[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeLong(value[i]);
            }
        } catch (IOException e) {}

    }

    /**
     * @see ghidra.util.ObjectStorage#putFloats(float[])
     */
    public void putFloats(float[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeFloat(value[i]);
            }
        } catch (IOException e) {}
    
    }

    /**
     * @see ghidra.util.ObjectStorage#putDoubles(double[])
     */
    public void putDoubles(double[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeDouble(value[i]);
            }
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#putStrings(String[])
     */
    public void putStrings(String[] value) {
        try {
            if (value == null) {
                out.writeInt(-1);
                return;
            }
            out.writeInt(value.length);
            for (int i = 0; i < value.length; i++) {
                out.writeObject(value[i]);
            }
        } catch (IOException e) {}
    }

    /**
     * @see ghidra.util.ObjectStorage#getInts()
     */
    public int[] getInts() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            int[] r = new int[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readInt();
            }
            return r;
        } catch (IOException e) {
        	return new int[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getBytes()
     */
    public byte[] getBytes() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            byte[] r = new byte[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readByte();
            }
            return r;
        } catch (IOException e) {
        	return new byte[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getShorts()
     */
    public short[] getShorts() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
           	short[] r = new short[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readShort();
            }
            return r;
        } catch (IOException e) {
        	return new short[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getLongs()
     */
    public long[] getLongs() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            long[] r = new long[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readLong();
            }
            return r;
        } catch (IOException e) {
        	return new long[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getFloats()
     */
    public float[] getFloats() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            float[] r = new float[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readFloat();
            }
            return r;
        } catch (IOException e) {
        	return new float[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getDoubles()
     */
    public double[] getDoubles() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            double[] r = new double[n];
            for(int i=0;i<n;i++) {
            	r[i] = in.readDouble();
            }
            return r;
        } catch (IOException e) {
        	return new double[0];
        }
    }

    /**
     * @see ghidra.util.ObjectStorage#getStrings()
     */
    public String[] getStrings() {
        try {
            int n = in.readInt();
            if (n < 0) {
            	return null;
            }
            String[] r = new String[n];
            for(int i=0;i<n;i++) {
            	r[i] = (String)in.readObject();
            }
            return r;
        } catch (Exception e) {
        	return new String[0];
        }
    }

}
