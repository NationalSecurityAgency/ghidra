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
package ghidra.file.formats.android.oat;

import java.io.IOException;
import java.util.*;

import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.*;
import ghidra.app.util.bin.format.elf.*;
import ghidra.file.formats.android.dex.format.DexHeader;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemBaseFactory;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.CryptoException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "androidoat", description = "Android OAT (for extracting embedded DEX files)", factory = GFileSystemBaseFactory.class)
public class OatFileSystem extends GFileSystemBase {

	private long baseOffset;
	private List<GFile> listing = new ArrayList<>();
	private List<OatDexFile> dexFileList = new ArrayList<>();

	public OatFileSystem(String fileSystemName, ByteProvider provider) {
		super(fileSystemName, provider);
	}

	@Override
	public boolean isValid(TaskMonitor monitor) throws IOException {
		try {
			byte e_ident_magic_num = provider.readByte(0);
			String e_ident_magic_str =
				new String(provider.readBytes(1, ElfConstants.MAGIC_STR_LEN));

			boolean magicMatch = ElfConstants.MAGIC_NUM == e_ident_magic_num &&
				ElfConstants.MAGIC_STR.equalsIgnoreCase(e_ident_magic_str);

			if (magicMatch) {
				ElfHeader elf =
					ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
				elf.parse();

				ElfSymbolTable dynamicSymbolTable = elf.getDynamicSymbolTable();
				ElfSymbol[] symbols = dynamicSymbolTable.getSymbols();
				for (ElfSymbol symbol : symbols) {
					if (OatConstants.SYMBOL_OAT_DATA.equals(symbol.getNameAsString())) {
						return true;
					}
				}

				//TODO check for OAT symbols (must be quick lookup)

//				FactoryBundledWithBinaryReader reader = new FactoryBundledWithBinaryReader( RethrowContinuesFactory.INSTANCE, provider, elf.isLittleEndian( ) );
//				for ( int i = 0 ; i < elf.e_phnum( ) ; ++i ) {
//					monitor.checkCanceled( );
//
//					long index = elf.e_phoff( ) + ( i * elf.e_phentsize ( ) );
//					reader.setPointerIndex(index);
//					int headerType = reader.peekNextInt();
//					if ( headerType == ElfProgramHeaderConstants.PT_DYNAMIC ) {
//						ElfProgramHeader programHeader = ElfProgramHeader.createElfProgramHeader( reader, elf );
//						
//					}
//				}
			}
		}
		catch (Exception e) {
			//ignore
		}
		return false;
	}

	@Override
	public void open(TaskMonitor monitor) throws IOException, CryptoException, CancelledException {
		try {
			monitor.setProgress(0);
			monitor.setMaximum(10);
			monitor.setMessage("Parsing ELF header...");
			monitor.incrementProgress(1);
			ElfHeader elf = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
			elf.parse();
			monitor.incrementProgress(1);

			ElfSectionHeader roDataSection = elf.getSection(ElfSectionHeaderConstants.dot_rodata);
			if (roDataSection == null) {
				//TODO should we check?
			}
			baseOffset = roDataSection.getOffset();

			monitor.setMessage("Parsing OAT header...");
			ByteProviderWrapper wrapper =
				new ByteProviderWrapper(provider, baseOffset, roDataSection.getSize());
			BinaryReader reader = new BinaryReader(wrapper, elf.isLittleEndian());
			OatHeader oatHeader = OatHeaderFactory.newOatHeader(reader);
			//oatHeader.parse( reader, null );
			OatHeaderFactory.parseOatHeader(oatHeader, reader, monitor);
			monitor.incrementProgress(1);

			dexFileList = oatHeader.getOatDexFileList();

			monitor.setProgress(0);
			monitor.setMaximum(dexFileList.size());
			monitor.setMessage("Creating OAT filesystem...");

			for (OatDexFile oatDexFileHeader : dexFileList) {
				monitor.checkCanceled();
				monitor.incrementProgress(1);
				DexHeader dexHeader = oatDexFileHeader.getDexHeader();
				if (dexHeader == null) {
					continue;
				}
				//add to file list, but remove the paths...
				StringTokenizer tokenizer =
					new StringTokenizer(oatDexFileHeader.getDexFileLocation(), "/");
				while (tokenizer.hasMoreTokens()) {
					monitor.checkCanceled();
					String token = tokenizer.nextToken();
					boolean isDirectory = tokenizer.hasMoreTokens();//last token is file name
					if (!isDirectory) {
						if (listing.isEmpty() && !token.endsWith(":classes.dex")) {
							token = token + ":classes.dex";//for some reason only the 2nd and on has this suffix
						}
						GFile file = GFileImpl.fromPathString(this, root, token, null, isDirectory,
							dexHeader.getFileSize());
						listing.add(file);
					}
				}
			}
		}
		catch (Exception e) {
			throw new IOException(e);
		}
	}

	@Override
	public void close() throws IOException {
		super.close();
		listing.clear();
		dexFileList = new ArrayList<>();//prevent UnmodifiableException
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		if (directory == null || directory.equals(root)) {
			return listing;
		}
		return null;
	}

	@Override
	public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
		int index = listing.indexOf(file);
		if (index < 0) {
			return FileAttributes.EMPTY;
		}

		OatDexFile oatDexFileHeader = dexFileList.get(index);
		return FileAttributes
				.of(FileAttribute.create("Oat location", oatDexFileHeader.getDexFileLocation()));
	}

	@Override
	public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {
		int index = listing.indexOf(file);
		if ( index < 0 ) {
			throw new IOException("Invalid / unknown file: " + file);
		}
		OatDexFile oatDexFileHeader = dexFileList.get(index);
		return new ByteProviderWrapper(provider, oatDexFileHeader.getDexFileOffset(),
			oatDexFileHeader.getDexHeader().getFileSize(), file.getFSRL());
	}

}
