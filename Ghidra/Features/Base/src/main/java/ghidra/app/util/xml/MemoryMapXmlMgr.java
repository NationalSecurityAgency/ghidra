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
package ghidra.app.util.xml;

import java.io.*;
import java.util.ArrayList;
import java.util.Arrays;

import org.xml.sax.SAXParseException;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;
import ghidra.util.XmlProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.*;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;

class MemoryMapXmlMgr {

	private Program program;
	private Memory memory;
	private AddressFactory factory;
	private MessageLog log;

	MemoryMapXmlMgr(Program program, MessageLog log) {
		this.program = program;
		this.memory = program.getMemory();
		this.factory = program.getAddressFactory();
		this.log = log;
	}

///////////////////////////////////////////////////////////////////////////////////////
//                            XML READ CURRENT DTD                                   //
///////////////////////////////////////////////////////////////////////////////////////

	void read(XmlPullParser parser, boolean overwriteConflicts, TaskMonitor monitor,
			String directory)
			throws SAXParseException, FileNotFoundException, CancelledException {

		XmlElement element = parser.next();
		element = parser.next();
		while (element.getName().equals("MEMORY_SECTION")) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			processMemoryBlock(element, parser, directory, program, monitor);
			element = parser.next();
		}
		if (element.isStart() || !element.getName().equals("MEMORY_MAP")) {
			throw new SAXParseException("Expected MEMORY_MAP end tag, got " + element.getName(),
				null, null, parser.getLineNumber(), parser.getColumnNumber());
		}
	}

	private void processMemoryBlock(XmlElement memorySectionElement, XmlPullParser parser,
			String directory, Program program, TaskMonitor monitor)
			throws FileNotFoundException {

		String name = memorySectionElement.getAttribute("NAME");
		String addrStr = memorySectionElement.getAttribute("START_ADDR");
		Address addr = XmlProgramUtilities.parseAddress(factory, addrStr);
		String overlayName = XmlUtilities.parseOverlayName(addrStr);
		int length = XmlUtilities.parseInt(memorySectionElement.getAttribute("LENGTH"));

		String permissions = memorySectionElement.getAttribute("PERMISSIONS");
		if (permissions == null) {
			permissions = "r";
		}
		boolean r = permissions.indexOf("r") >= 0;
		boolean w = permissions.indexOf("w") >= 0;
		boolean x = permissions.indexOf("x") >= 0;

		String volatility = memorySectionElement.getAttribute("VOLATILE");
		boolean isVolatile = "y".equals(volatility);

		String comment = memorySectionElement.getAttribute("COMMENT");

		try {
			XmlElement element = parser.peek();

			if (element.getName().equals("MEMORY_CONTENTS")) {
				byte[] bytes = new byte[length];
				Arrays.fill(bytes, (byte) 0xff);

				while (element.getName().equals("MEMORY_CONTENTS")) {
					element = parser.next();
					Address startAddr = addr;
					if (element.hasAttribute("START_ADDR")) {
						String startAddrStr = element.getAttribute("START_ADDR");
						int index = startAddrStr.indexOf("::");
						if (index > 0) {
							startAddrStr = startAddrStr.substring(index + 2);
						}
						startAddr = XmlProgramUtilities.parseAddress(factory, startAddrStr);
					}
					String fileName = element.getAttribute("FILE_NAME");
					int fileOffset = XmlUtilities.parseInt(element.getAttribute("FILE_OFFSET"));
					int contentLen = element.hasAttribute("LENGTH")
							? XmlUtilities.parseInt(element.getAttribute("LENGTH"))
							: length;
					setData(bytes, (int) startAddr.subtract(addr), directory, fileName, fileOffset,
						contentLen, log);

					parser.next();//consume my end element...

					element = parser.peek();//get next start of contents or end of section
				}
				if (overlayName != null) {
					MemoryBlock block =
						MemoryBlockUtils.createInitializedBlock(program, true, overlayName, addr,
							new ByteArrayInputStream(bytes),
							bytes.length, comment, null, r, w, x, log, monitor);
					if (block != null) {
						block.setVolatile(isVolatile);
						if (!name.equals(overlayName)) {
							block.setName(name);
						}
					}
				}
				else {

					MemoryBlock block = MemoryBlockUtils.createInitializedBlock(program, false,
						name, addr, new ByteArrayInputStream(bytes), bytes.length, comment, null,
						r, w, x, log, monitor);
					if (block != null) {
						block.setVolatile(isVolatile);
					}
				}
			}
			else if (element.getName().equals("BIT_MAPPED")) {
				Address sourceAddr = factory.getAddress(element.getAttribute("SOURCE_ADDRESS"));

				MemoryBlock block = MemoryBlockUtils.createBitMappedBlock(program, overlayName,
					addr, sourceAddr, length, comment, comment, r, w, x, false, log);
				if (block != null) {
					block.setVolatile(isVolatile);
				}
				parser.next(); // consume end of Bit_mapped
			}
			else if (element.getName().equals("BYTE_MAPPED")) {
				Address sourceAddr = factory.getAddress(element.getAttribute("SOURCE_ADDRESS"));

				MemoryBlock block = MemoryBlockUtils.createByteMappedBlock(program, overlayName,
					addr, sourceAddr, length, comment, comment, r, w, x, false, log);
				if (block != null) {
					block.setVolatile(isVolatile);
				}
				parser.next(); // consume end of Bit_mapped
			}
			else {
				MemoryBlock block = MemoryBlockUtils.createUninitializedBlock(program,
					overlayName != null, name, addr, length, comment, null, r, w, x, log);
				if (block != null) {
					block.setVolatile(isVolatile);
					if (overlayName != null && !name.equals(overlayName)) {
						block.setName(name);
					}
				}
			}
		}
		catch (FileNotFoundException e) {
			throw e;
		}
		catch (Exception e) {
			log.appendException(e);
		}
		finally {
			parser.discardSubTree(memorySectionElement);
		}
	}

	private void setData(byte[] bytes, int offset, String directory, String fileName,
			int fileOffset, int length, MessageLog log) throws IOException {
		File f = new File(directory, fileName);
		RandomAccessFile binfile = new RandomAccessFile(f, "r");
		//binfile.seek(fileOffset);
		try {
			int pos = 0;
			while (pos < length) {
				int readLen = (512 * 1024);
				if ((readLen + pos) > length) {
					readLen = length - pos;
				}
				binfile.seek(fileOffset + pos);
				readLen = binfile.read(bytes, offset + pos, readLen);
				if (readLen <= 0) {
					break;
				}
				pos += readLen;
			}
		}
		catch (IndexOutOfBoundsException e) {
			log.appendMsg("Invalid bin file offset " + offset + " with length " + length);
		}
		binfile.close();
	}

//    private void processBlockV1(XmlElement element, XmlPullParser parser, String directory) {
//        try {
//            String name = element.getAttribute("NAME");
//            Address start = factory.getAddress(element.getAttribute("START"));
//            Address end = factory.getAddress(element.getAttribute("END"));
//            String permissions = element.getAttribute("PERMISSIONS");
//            String comment = element.getAttribute("COMMENT");
//            int length = (int) end.subtract(start);
//            element = parser.next();
//
//            if (element.getName().equals("MEMORY_CONTENTS")) {
//                byte[] bytes = new byte[length];
//                Arrays.fill(bytes, (byte) 0xff);
//
//                String fileName = element.getAttribute("FILENAME");
//                int fileOffset = XmlUtilities.parseInt(element.getAttribute("FILE_OFFSET"));
//                setData(bytes, 0, directory, fileName, fileOffset, length, log);
//                memory.createInitializedBlock(name, start, new ByteArrayInputStream(bytes), bytes.length, null);
//            }
//            else {
//                memory.createUninitializedBlock(name, start, length);
//            }
//        }
//        catch (Exception e) {
//            log.appendMsg(e.getMessage());
//        }
//        parser.discardSubTree("MEMORY_BLOCK");
//    }

///////////////////////////////////////////////////////////////////////////////////////
//   						 XML WRITE CURRENT DTD                                   //
///////////////////////////////////////////////////////////////////////////////////////

	void write(XmlWriter writer, AddressSetView addrs, TaskMonitor monitor, boolean isWriteContents,
			File file) throws IOException, CancelledException {
		monitor.setMessage("Writing MEMORY MAP ...");

		BytesFile bf = isWriteContents ? new BytesFile(file.getAbsolutePath()) : null;

		writer.startElement("MEMORY_MAP");

		AddressRangeIterator iter = addrs.getAddressRanges();
		while (iter.hasNext()) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}
			AddressRange range = iter.next();
			RangeBlock rb = new RangeBlock(program.getAddressFactory(), program.getMemory(), range);
			for (int i = 0; i < rb.getRanges().length; ++i) {
				writeBlock(writer, rb.getRanges()[i], rb.getBlocks()[i], bf, isWriteContents);
			}
		}

		if (isWriteContents) {
			bf.close();
		}

		writer.endElement("MEMORY_MAP");

	}

	private void writeBlock(XmlWriter writer, AddressRange range, MemoryBlock block,
			BytesFile bytesFile, boolean isWriteContents) throws IOException {

		XmlAttributes attrs = new XmlAttributes();
		attrs.addAttribute("NAME", block.getName());
		attrs.addAttribute("START_ADDR", XmlProgramUtilities.toString(range.getMinAddress()));
		attrs.addAttribute("LENGTH", range.getLength(), true);
		String permissions = "r";//always set to read...
		if (block.isWrite()) {
			permissions += "w";
		}
		if (block.isExecute()) {
			permissions += "x";
		}
		attrs.addAttribute("PERMISSIONS", permissions);
		if (block.getComment() != null) {
			attrs.addAttribute("COMMENT", block.getComment());
		}

		if (block.isVolatile()) {
			attrs.addAttribute("VOLATILE", true);
		}

		writer.startElement("MEMORY_SECTION", attrs);

		if (block.getType() == MemoryBlockType.BIT_MAPPED) {
			// bit mapped blocks can only have one sub-block
			MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
			attrs.addAttribute("SOURCE_ADDRESS",
				info.getMappedRange().get().getMinAddress().toString());
			writer.startElement("BIT_MAPPED", attrs);
			writer.endElement("BIT_MAPPED");
		}
		else if (block.getType() == MemoryBlockType.BYTE_MAPPED) {
			// byte mapped blocks can only have one sub-block
			MemoryBlockSourceInfo info = block.getSourceInfos().get(0);
			attrs.addAttribute("SOURCE_ADDRESS",
				info.getMappedRange().get().getMinAddress().toString());
			writer.startElement("BYTE_MAPPED", attrs);
			writer.endElement("BYTE_MAPPED");
		}
		else if (block.isInitialized() && isWriteContents) {
			attrs.addAttribute("FILE_NAME", bytesFile.getFileName());
			attrs.addAttribute("FILE_OFFSET", bytesFile.getOffset(), true);

			writer.startElement("MEMORY_CONTENTS", attrs);
			writer.endElement("MEMORY_CONTENTS");
			bytesFile.writeBytes(memory, range);
		}

		writer.endElement("MEMORY_SECTION");
	}
}

class RangeBlock {
	private ArrayList<AddressRange> rangeList = new ArrayList<>();
	private ArrayList<MemoryBlock> blockList = new ArrayList<>();

	RangeBlock(AddressFactory af, Memory memory, AddressRange range) {
		AddressSet set = new AddressSet(range);
		while (!set.isEmpty()) {
			MemoryBlock block = memory.getBlock(set.getMinAddress());
			set.deleteRange(block.getStart(), block.getEnd());
			rangeList.add(range.intersect(new AddressRangeImpl(block.getStart(), block.getEnd())));
			blockList.add(block);
		}
	}

	AddressRange[] getRanges() {
		AddressRange[] ranges = new AddressRange[rangeList.size()];
		rangeList.toArray(ranges);
		return ranges;
	}

	MemoryBlock[] getBlocks() {
		MemoryBlock[] blocks = new MemoryBlock[rangeList.size()];
		blockList.toArray(blocks);
		return blocks;
	}
}

class BytesFile {
	private OutputStream os;
	private String fileName;
	private int bytesWritten;

	BytesFile(String fileName) throws IOException {
		if (fileName.endsWith(".xml")) {
			fileName = fileName.substring(0, fileName.length() - 4);
		}
		fileName += ".bytes";
		File file = new File(fileName);
		this.fileName = file.getName();
		if (file.exists()) {
			file.delete();
		}
		os = new BufferedOutputStream(new FileOutputStream(file));
	}

	void close() throws IOException {
		os.close();
	}

	String getFileName() {
		return fileName;
	}

	int getOffset() {
		return bytesWritten;
	}

	void writeBytes(Memory memory, AddressRange range) throws IOException {
		try {
			int BUFSIZE = 32 * 1024;
			long size = range.getLength();
			byte[] buf = new byte[(int) Math.min(size, BUFSIZE)];
			Address addr = range.getMinAddress();
			int n = 0;
			while (size > 0) {
				addr = addr.addNoWrap(n);
				n = memory.getBytes(addr, buf);
				os.write(buf, 0, n);
				bytesWritten += n;
				size -= n;
			}
		}
		catch (AddressOverflowException e) {
			throw new IOException(e.getMessage());
		}
		catch (MemoryAccessException e) {
			throw new IOException(e.getMessage());
		}
		catch (IOException e) {
			throw new IOException(e.getMessage());
		}
	}
}
