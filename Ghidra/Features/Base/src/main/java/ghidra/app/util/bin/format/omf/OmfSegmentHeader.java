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
package ghidra.app.util.bin.format.omf;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.OmfLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

public class OmfSegmentHeader extends OmfRecord {
	private byte segAttr;		// first byte of Segment Attributes
	private int frameNumber;
	private int offset;
	private long segmentLength;
	private int segmentNameIndex;
	private int classNameIndex;
	private int overlayNameIndex;
	private String segmentName;
	private String className;
	private String overlayName;
	private boolean isCode;
	private boolean isReadable;
	private boolean isWritable;
	private boolean isExecutable;
	private long vma = -1;				// assigned (by linker) starting address of segment -1 means unset
	private ArrayList<OmfData> dataBlocks = new ArrayList<OmfData>();

	OmfSegmentHeader(int num,int datatype) {
		// generate a special Borland header
		segAttr = (byte)0xa9;
		segmentLength = 0;
		segmentNameIndex = 0;
		classNameIndex = 0;
		overlayNameIndex = 0;
		overlayName = "";
		if (datatype == 1) {
			segmentName = "EXTRATEXT_";
		}
		else if (datatype == 2) {
			segmentName = "EXTRADATA_";
		}
		else {
			segmentName = "EXTRA_";
		}
		segmentName = segmentName+Integer.toString(num);
		if (datatype == 1) {
			// Treat as a text segment
			className = "TEXT";
			isCode = true;
			isReadable = true;
			isWritable = false;
			isExecutable = true;
		}
		else {
			className = "DATA";
			isCode = false;
			isReadable = true;
			isWritable = true;
			isExecutable = false;
		}
	}
	
	public OmfSegmentHeader(BinaryReader reader) throws IOException {
		readRecordHeader(reader);
		boolean hasBigFields = hasBigFields();
		segAttr = reader.readNextByte();
		int A = (segAttr >> 5) & 7;
		if (A == 0) {
			frameNumber = reader.readNextShort() & 0xffff;
			offset = reader.readNextByte() & 0xff;
			vma = (long)frameNumber + offset;
		}
		segmentLength = OmfRecord.readInt2Or4(reader, hasBigFields) & 0xffffffffL;
		segmentNameIndex = OmfRecord.readIndex(reader);
		classNameIndex = OmfRecord.readIndex(reader);
		overlayNameIndex = OmfRecord.readIndex(reader);
		readCheckSumByte(reader);
		int B = (segAttr>>1) & 1;
		if (B==1) {		// Ignore the segmentLength field
			if (getRecordType() == OmfRecord.SEGDEF) {
				segmentLength = 0x10000L;		// Exactly 64K segment
			}
			else {
				segmentLength = 0x100000000L;	// Exactly 4G segment
			}
		}
	}
	
	/**
	 * @return true if this is a code segment
	 */
	public boolean isCode() {
		return isCode;
	}
	
	/**
	 * @return true if this segment is readable
	 */
	public boolean isReadable() {
		return isReadable;
	}
	
	/**
	 * @return true if this segment is writable
	 */
	public boolean isWritable() {
		return isWritable;
	}
	
	/**
	 * @return true if this segment is executable
	 */
	public boolean isExecutable() {
		return isExecutable;
	}

	/**
	 * @return the segment selector needed for this object
	 */
	public int getFrameDatum() {
		return 0;				// TODO:  Need to fill in a real segment selector
	}
	
	/**
	 * @param language is the Program language for this binary
	 * @return the starting Address for this segment
	 */
	public Address getAddress(Language language) {
		AddressSpace addrSpace;

		if (isCode) {
			addrSpace = language.getDefaultSpace();
		} else {
			addrSpace = language.getDefaultDataSpace();
		}
		return addrSpace.getAddress(vma);		
	}
	
	/**
	 * @return the name of this segment
	 */
	public String getName() {
		return segmentName;
	}
	
	/**
	 * @return the class name of this segment
	 */
	public String getClassName() {
		return className;
	}
	
	/**
	 * @return the name of the overlay, or the empty string
	 */
	public String getOverlayName() {
		return overlayName;
	}

	/**
	 * @return the load image address for this segment
	 */
	public long getStartAddress() {
		return vma;
	}
	
	/**
	 * @return the length of the segment in bytes
	 */
	public long getSegmentLength() {
		return segmentLength;
	}
	
	/**
	 * @return the alignment required for this segment
	 */
	public int getAlignment() {
		return (segAttr >> 5) & 0x7;
	}
	
	/**
	 * @return special combining rules for this segment
	 */
	public int getCombine() {
		return (segAttr >> 2) & 0x7;
	}

	/**
	 * @return true if this block uses filler other than zero bytes
	 */
	public boolean hasNonZeroData() {
		for (OmfData block : dataBlocks) {
			if (!block.isAllZeroes()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Sort the data-blocks within this segment
	 */
	protected void sortData() {
		Collections.sort(dataBlocks);
	}
	
	/**
	 * Get an InputStream that reads in the raw data for this segment
	 * @param reader is the image file reader
	 * @param log the log
	 * @return the InputStream
	 * @throws IOException for problems reading from the image file
	 */
	public InputStream getRawDataStream(BinaryReader reader, MessageLog log) throws IOException {
		return new SectionStream(reader, log);
	}
	
	/**
	 * Given the first possible address where this segment can reside, relocate the
	 * segment based on this address and alignment considerations.
	 * @param firstValidAddress is the first possible Address for the segment
	 * @param alignOverride if non-negative, overrides alignment info from the segment header
	 * @return the next possible address for following segments
	 * @throws OmfException for bad alignment information
	 */
	protected long relocateSegment(long firstValidAddress, int alignOverride) throws OmfException {
		int align =  getAlignment();
		if (alignOverride >= 0) {
			align = alignOverride;
		}
		switch(align) {
		case 0:			// Absolute segment, not relocatable
			throw new OmfException("Trying to relocate an absolute segment");
		case 1:			// Byte aligned
			break;		// Keep the first valid address
		case 2:			// 2-byte aligned
			firstValidAddress = (firstValidAddress+1 ) & 0xfffffffffffffffeL;
			break;
		case 3:			// 16-byte aligned
			firstValidAddress = (firstValidAddress+15) & 0xfffffffffffffff0L;
			break;
		case 4:			// "page" aligned,  assume 4096
			firstValidAddress = (firstValidAddress+4095) & 0xfffffffffffff000L;
			break;
		case 5:			// 4-byte aligned
			firstValidAddress = (firstValidAddress+3) & 0xfffffffffffffffcL;
			break;
		default:
			throw new OmfException("Unsupported alignment type");
		}
		vma = firstValidAddress;
		firstValidAddress = vma + segmentLength;
		return firstValidAddress;
	}
	
	/**
	 * Resolve special names from the name list such as: segment, class, overlay, names.
	 * This routine also determines the read/write/execute permissions for the segment
	 * based on the class name.
	 * @param nameList is the array of names associated with the file
	 * @throws OmfException for improper name indices
	 */
	protected void resolveNames(ArrayList<String> nameList) throws OmfException {
		if (segmentNameIndex == 0) {
			segmentName = "";			// Name is unused
		}
		else {
			if (segmentNameIndex > nameList.size()) {
				throw new OmfException("Segment name index out of bounds");
			}
			segmentName = nameList.get(segmentNameIndex - 1);
		}
		if (classNameIndex == 0) {
			className = "";
		}
		else {
			if (classNameIndex > nameList.size()) {
				throw new OmfException("Class name index out of bounds");
			}
			className = nameList.get(classNameIndex - 1);
		}
		if (overlayNameIndex == 0) {
			overlayName = "";
		}
		else {
			if (overlayNameIndex > nameList.size()) {
				throw new OmfException("Overlay name index out of bounds");
			}
			overlayName = nameList.get(overlayNameIndex - 1);
		}
		
		// Once we know the class name, we can make some educated guesses about read/write/exec permissions
		isReadable = true;
		if (className.equals("CODE") || className.equals("code")) {
			isCode = true;
			isWritable = false;
			isExecutable = true;
		}
		else {
			isCode = false;
			isWritable = true;
			isExecutable = false;
		}
	}
	
	/**
	 * Add an explicit data-block to this segment.
	 * @param rec is the data-block
	 */
	protected void addEnumeratedData(OmfEnumeratedData rec) {
		dataBlocks.add(rec);
	}
	
	/**
	 * Add an explicit data-block to this segment that might extend
	 * the length of this segment.  Borland compilers in particular produce
	 * data-blocks that can extend the segment in this way.
	 * @param rec is the data-block
	 */
	protected void appendEnumeratedData(OmfEnumeratedData rec) {
		long blockend = rec.getDataOffset() + rec.getLength();
		if (blockend > segmentLength) {
			segmentLength = blockend;
		}
		dataBlocks.add(rec);
	}
	
	/**
	 * Add a compressed-form data-block to this segment
	 * @param rec is the data-block
	 */
	protected void addIteratedData(OmfIteratedData rec) {
		dataBlocks.add(rec);
	}
	
	/**
	 * An InputStream that produces the bytes for the dataBlocks in this segment.
	 * It runs through the ordered {@link OmfData} in turn.  It pads with zeroes,
	 * wherever part of the segment is not covered by a data block.
	 */
	public class SectionStream extends InputStream {
		private BinaryReader reader;
		private MessageLog log;
		private long pointer;		// Overall position within segment, relative to starting address
		private byte[] buffer;		// Current buffer
		private int bufferpointer;	// current index into buffer
		private int dataUpNext;		// Index of next data section OmfIteratedData/OmfEnumeratedData to be buffered 
		
		public SectionStream(BinaryReader reader, MessageLog log) throws IOException {
			super();
			this.reader = reader;
			this.log = log;
			pointer = 0;
			dataUpNext = 0;
			if (pointer < segmentLength) {
				establishNextBuffer();
			}
		}
		
		/**
		 * Fill the next buffer of bytes being provided by this stream.
		 * @throws IOException for problems with the file image reader
		 */
		private void establishNextBuffer() throws IOException {
			while (dataUpNext < dataBlocks.size()) {
				OmfData data = dataBlocks.get(dataUpNext);
				if (pointer < data.getDataOffset()) {
					// We have some fill to produce before the next section
					long size = data.getDataOffset() - pointer;
					if (size > OmfLoader.MAX_UNINITIALIZED_FILL) {
						throw new IOException("Unfilled hole in OMF data blocks for segment: "+segmentName);
					}
					buffer = new byte[(int)size];
					for(int i=0;i<size;++i) {
						buffer[i] = 0;
					}
					bufferpointer = 0;
					return;
				}
				else if (pointer == data.getDataOffset()) {
					buffer = data.getByteArray(reader);
					bufferpointer = 0;
					dataUpNext++;
					if (buffer.length == 0) {
						continue;
					}
					return;
				}
				else {
					dataUpNext++;
					throw new IOException(String.format(
						"Segment %s:%s has bad data offset (0x%x) in data block %d...skipping.",
						segmentName, className, data.getDataOffset(), dataUpNext - 1));
				}
			}
			// We may have filler after the last block
			long size = segmentLength - pointer;
			if (size > OmfLoader.MAX_UNINITIALIZED_FILL) {
				throw new IOException("Large hole at the end of OMF segment: "+segmentName);
			}
			buffer = new byte[(int)size];
			for(int i=0;i<size;++i) {
				buffer[i] = 0;
			}
			bufferpointer = 0;			
		}
		
		@Override
		public int read() throws IOException {
			if (pointer < segmentLength) {
				if (bufferpointer < buffer.length) {
					pointer++;
					return buffer[bufferpointer++] & 0xff;
				}
				try {
					establishNextBuffer();
					pointer++;
					return buffer[bufferpointer++] & 0xff;		// Don't allow sign-extension to happen
				}
				catch (IOException e) {
					log.appendMsg(e.getMessage());
				}
			}
			return -1;
		}
		
	}
}
