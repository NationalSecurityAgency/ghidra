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
package db;

import ghidra.util.datastruct.IntIntHashtable;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.NoValueException;

import java.io.File;
import java.io.IOException;

import db.buffers.*;

/**
 * <code>DBParms</code> manages 4-byte integer parameters associated with a database 
 * and stored as the first buffer (ID 0) in the buffer file.  The maximum number of 
 * parameters is determined by the .
 */
class DBParms {
	
	/**
	 * Parameter number for the Master Table Root Buffer ID
	 */
	static int MASTER_TABLE_ROOT_BUFFER_ID_PARM = 0;
	static int DATABASE_ID_HIGH_PARM = 1;
	static int DATABASE_ID_LOW_PARM = 2;

	// NOTE: DBParms used to use a ChainedBuffer which was dropped since DBParms remains very small
	// and we need the ability to patch DBParms (poke) which can be very complicated with a chained buffer
	private static final int NODE_TYPE_SIZE = 1;
	private static final int DATA_LENGTH_SIZE = 4;
	private static final int VERSION_SIZE = 1; 
	private static final int NODE_TYPE_OFFSET = 0;
	private static final int DATA_LENGTH_OFFSET = NODE_TYPE_SIZE;
	private static final int VERSION_OFFSET = DATA_LENGTH_OFFSET + DATA_LENGTH_SIZE;
	private static final int PARM_BASE_OFFSET = VERSION_OFFSET + VERSION_SIZE;

	private static final byte VERSION = 1;
	
	private BufferMgr bufferMgr;
	private int size;

	private IntIntHashtable cache = new IntIntHashtable();
	
	/**
	 * Construct a new or existing parameter buffer.
	 * @param bufferMgr buffer manager
	 * @param create if true storage buffers will be allocated with the bufferMgr.
	 * This must be the first buffer allocation - if buffer 0 is not available
	 * a runtime exception will be thrown.
	 * @throws IOException
	 */
	DBParms(BufferMgr bufferMgr, boolean create) throws IOException {
		this.bufferMgr = bufferMgr;
		if (create) {
			DataBuffer buffer = null;
			try {
				buffer = bufferMgr.createBuffer();
				if (buffer.getId() != 0) {
					throw new AssertException("DBParms must be first buffer allocation");
				}
				buffer.clear();
				buffer.putByte(NODE_TYPE_OFFSET, NodeMgr.CHAINED_BUFFER_DATA_NODE); // we mimic a single buffer chained-buffer
				buffer.putInt(DATA_LENGTH_OFFSET, VERSION_SIZE);
				buffer.putByte(VERSION_OFFSET, VERSION);
			}
			finally {
				if (buffer != null) {
					bufferMgr.releaseBuffer(buffer);
				}
			}
		}
		refresh();
	}
	
	/**
	 * Get the buffer offset for a specified parameter
	 * @param parm parameter number
	 * @return parameter offset
	 */
	private static int getOffset(int parm) {
		return PARM_BASE_OFFSET + (parm * 4);
	}
	
	/**
	 * Poke a modified DBParam into a database buffer file.
	 * WARNING! Use with extreme caution since this immediately modifies
	 * the original file in-place and could destroy data if used
	 * improperly.
	 * @param file
	 * @param parm
	 * @param value
	 * @throws IOException
	 */
	static void poke(File file, int parm, int value) throws IOException {
		DataBuffer buffer = LocalBufferFile.peek(file, 0);
		if (buffer.getByte(NODE_TYPE_OFFSET) != NodeMgr.CHAINED_BUFFER_DATA_NODE) {
			throw new AssertException("Unexpected DBParms buffer node type");
		}
		if (buffer.getByte(VERSION_OFFSET) != VERSION) {
			throw new AssertException("Unsupported DBParms format");
		}
		
		storeParm(parm, value, buffer);
		
		LocalBufferFile.poke(file, 0, buffer);
	}
	
	private static void storeParm(int parm, int value, DataBuffer buffer) {
		int maxParmCnt = (buffer.length() - PARM_BASE_OFFSET) / 4;
		if (parm < 0 || parm >= maxParmCnt) {
			throw new ArrayIndexOutOfBoundsException("Invalid parameter index: " + parm);
		}
		int size = (buffer.getInt(DATA_LENGTH_OFFSET) - VERSION_SIZE) / 4;
		if (parm >= size) {
			// expand parameter space
			int dataLen = (parm + 1) * 4;
			buffer.putInt(DATA_LENGTH_OFFSET, dataLen + VERSION_SIZE);
		}
		buffer.putInt(getOffset(parm), value);
	}
	
	/**
	 * Set a parameter value.  If parameter space is expanded to accommodate this 
	 * parameter, all allocated parameters will be initialized to -1
	 * @param parm parameter number
	 * @param value parameter value
	 * @throws IOException thrown if an IO error occurs
	 */
	void set(int parm, int value) throws IOException {
		DataBuffer buffer = bufferMgr.getBuffer(0);
		try {
			storeParm(parm, value, buffer);
			if (parm >= size) {
				// initialize unused parameters parameter space
				for (int i = size; i < parm; i++) {
					cache.put(i, 0);
				}
				size = parm + 1;
			}
			cache.put(parm, value);
		}
		finally {
			bufferMgr.releaseBuffer(buffer);
		}
	}

	/**
	 * Get a parameter value
	 * @param parm parameter number
	 * @return parameter value
	 * @throws IOException thrown if an IO error occurs
	 * @throws ArrayIndexOutOfBoundsException if index outside of allocated
	 * parameter space.
	 */
	int get(int parm) throws IOException, ArrayIndexOutOfBoundsException {
		try {
			return cache.get(parm);
		}
		catch (NoValueException e) {
			throw new ArrayIndexOutOfBoundsException();
		}
	}
	
	/**
	 * Refresh parameters from an existing parameter buffer.
	 * @throws IOException thrown if an IO error occurs.
	 */
	void refresh() throws IOException {
		DataBuffer buffer = bufferMgr.getBuffer(0);
		try {
			if (buffer.getByte(NODE_TYPE_OFFSET) != NodeMgr.CHAINED_BUFFER_DATA_NODE) {
				throw new AssertException("Unexpected DBParms buffer node type");
			}
			if (buffer.getByte(VERSION_OFFSET) != VERSION) {
				throw new AssertException("Unsupported DBParms format");
			}
			size = (buffer.getInt(DATA_LENGTH_OFFSET) - VERSION_SIZE) / 4;
			cache = new IntIntHashtable();
			for (int i = 0; i < size; i++) {
				cache.put(i, buffer.getInt(getOffset(i)));
			}
		}
		finally {
			bufferMgr.releaseBuffer(buffer);
		}
	}

}
