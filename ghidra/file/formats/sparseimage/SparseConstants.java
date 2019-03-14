/* ###
 * IP: Apache License 2.0
 * NOTE: Based on the simg2img code from The Android Open Source Project
 */
package ghidra.file.formats.sparseimage;

public final class SparseConstants {
	
	public final static int SPARSE_HEADER_MAGIC = 0xED26FF3A;
	
	public final static short CHUNK_TYPE_RAW = (short)0xCAC1;
	public final static short CHUNK_TYPE_FILL = (short)0xCAC2;
	public final static short CHUNK_TYPE_DONT_CARE = (short)0xCAC3;
	public final static short CHUNK_TYPE_CRC32 = (short)0xCAC4;
	
	public final static int MAJOR_VERSION_NUMBER = 1;

}
