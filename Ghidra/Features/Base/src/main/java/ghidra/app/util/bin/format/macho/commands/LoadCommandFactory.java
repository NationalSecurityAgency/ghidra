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
package ghidra.app.util.bin.format.macho.commands;

import static ghidra.app.util.bin.format.macho.commands.LoadCommandTypes.*;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.format.macho.MachException;
import ghidra.app.util.bin.format.macho.MachHeader;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheHeader;
import ghidra.app.util.bin.format.macho.dyld.DyldCacheMappingInfo;
import ghidra.app.util.bin.format.macho.threadcommand.ThreadCommand;
import ghidra.app.util.opinion.DyldCacheUtils.SplitDyldCache;
import ghidra.util.Msg;

/**
 * A factory used to create {@link LoadCommand}s 
 */
public class LoadCommandFactory {

	/**
	 * Create and parses a {@link LoadCommand}
	 * <p>
	 * NOTE: Parsing {@link LoadCommand}s whose data lives in the __LINKEDIT segment require that
	 * the __LINKEDIT {@link SegmentCommand} have already been parsed.  Thus, it is required that
	 * this method be called on {@link SegmentCommand}s before other types of {@link LoadCommand}s.
	 * 
	 * @param reader A {@link BinaryReader reader} that points to the start of the load command
	 * @param header The {@link MachHeader header} associated with this load command	 
	 * @param splitDyldCache The {@link SplitDyldCache} that this header resides in.  Could be null
	 *   if a split DYLD cache is not being used.
	 * @return A new {@link LoadCommand}
	 * @throws IOException if an IO-related error occurs while parsing
	 * @throws MachException if the load command is invalid
	 */
	public static LoadCommand getLoadCommand(BinaryReader reader, MachHeader header,
			SplitDyldCache splitDyldCache) throws IOException, MachException {
		int type = reader.peekNextInt();
		switch (type) {
			case LC_SEGMENT:
				return new SegmentCommand(reader, header.is32bit());
			case LC_SYMTAB:
				return new SymbolTableCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache), header);
			case LC_SYMSEG:
				return new SymbolCommand(reader);
			case LC_THREAD:
			case LC_UNIXTHREAD:
				return new ThreadCommand(reader, header);
			case LC_LOADFVMLIB:
			case LC_IDFVMLIB:
				return new FixedVirtualMemorySharedLibraryCommand(reader);
			case LC_IDENT:
				return new IdentCommand(reader);
			case LC_FVMFILE:
				return new FixedVirtualMemoryFileCommand(reader);
			case LC_PREPAGE:
				return new UnsupportedLoadCommand(reader, type);
			case LC_DYSYMTAB:
				return new DynamicSymbolTableCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache), header);
			case LC_LOAD_DYLIB:
			case LC_ID_DYLIB:
			case LC_LOAD_UPWARD_DYLIB:
				return new DynamicLibraryCommand(reader);
			case LC_LOAD_DYLINKER:
			case LC_ID_DYLINKER:
			case LC_DYLD_ENVIRONMENT:
				return new DynamicLinkerCommand(reader);
			case LC_PREBOUND_DYLIB:
				return new PreboundDynamicLibraryCommand(reader);
			case LC_ROUTINES:
				return new RoutinesCommand(reader, header.is32bit());
			case LC_SUB_FRAMEWORK:
				return new SubFrameworkCommand(reader);
			case LC_SUB_UMBRELLA:
				return new SubUmbrellaCommand(reader);
			case LC_SUB_CLIENT:
				return new SubClientCommand(reader);
			case LC_SUB_LIBRARY:
				return new SubLibraryCommand(reader);
			case LC_TWOLEVEL_HINTS:
				return new TwoLevelHintsCommand(reader);
			case LC_PREBIND_CKSUM:
				return new PrebindChecksumCommand(reader);
			case LC_LOAD_WEAK_DYLIB:
				return new DynamicLibraryCommand(reader);
			case LC_SEGMENT_64:
				return new SegmentCommand(reader, header.is32bit());
			case LC_ROUTINES_64:
				return new RoutinesCommand(reader, header.is32bit());
			case LC_UUID:
				return new UuidCommand(reader);
			case LC_RPATH:
				return new RunPathCommand(reader);
			case LC_CODE_SIGNATURE:
			case LC_SEGMENT_SPLIT_INFO:
			case LC_DATA_IN_CODE:
			case LC_OPTIMIZATION_HINT:
			case LC_DYLIB_CODE_SIGN_DRS:
				return new LinkEditDataCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache));
			case LC_REEXPORT_DYLIB:
				return new DynamicLibraryCommand(reader);
			case LC_ENCRYPTION_INFO:
			case LC_ENCRYPTION_INFO_64:
				return new EncryptedInformationCommand(reader, header.is32bit());
			case LC_DYLD_INFO:
			case LC_DYLD_INFO_ONLY:
				return new DyldInfoCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache), header);
			case LC_VERSION_MIN_MACOSX:
			case LC_VERSION_MIN_IPHONEOS:
			case LC_VERSION_MIN_TVOS:
			case LC_VERSION_MIN_WATCHOS:
				return new VersionMinCommand(reader);
			case LC_FUNCTION_STARTS:
				return new FunctionStartsCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache));
			case LC_MAIN:
				return new EntryPointCommand(reader);
			case LC_SOURCE_VERSION:
				return new SourceVersionCommand(reader);
			case LC_LAZY_LOAD_DYLIB:
				return new DynamicLibraryCommand(reader);
			case LC_LINKER_OPTIONS:
				return new LinkerOptionCommand(reader);
			case LC_BUILD_VERSION:
				return new BuildVersionCommand(reader);
			case LC_DYLD_EXPORTS_TRIE:
				return new DyldExportsTrieCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache));
			case LC_DYLD_CHAINED_FIXUPS:
				return new DyldChainedFixupsCommand(reader,
					getLinkEditReader(reader, header, splitDyldCache));
			case LC_FILESET_ENTRY:
				return new FileSetEntryCommand(reader);
			default:
				Msg.warn(header, "Unsupported load command " + Integer.toHexString(type));
				return new UnsupportedLoadCommand(reader, type);
		}
	}

	/**
	 * Gets a {@link BinaryReader} that points to the given {@link MachHeader Mach-O header's} 
	 * __LINKEDIT segment.  Note that this segment may live in a different provider than
	 * the Mach-O header if a {@link SplitDyldCache} is being used.
	 * <p>
	 * NOTE: This method assumes that the __LINKEDIT segment {@link LoadCommand} has already been
	 * parsed.
	 * 
	 * @param reader The {@link BinaryReader} used to read the given Mach-O header
	 * @param header The {@link MachHeader Mach-O header}
	 * @param splitDyldCache The {@link SplitDyldCache}, or null if that is not being used
	 * @return A {@link BinaryReader} that points to the given {@link MachHeader Mach-O header's} 
	 *   __LINKEDIT segment
	 * @throws MachException If the __LINKEDIT segment was not found
	 */
	private static BinaryReader getLinkEditReader(BinaryReader reader, MachHeader header,
			SplitDyldCache splitDyldCache) throws MachException {
		SegmentCommand linkEdit = header.getSegment(SegmentNames.SEG_LINKEDIT);
		if (linkEdit == null) {
			throw new MachException("__LINKEDIT segment not found");
		}
		if (splitDyldCache == null) {
			return reader.clone(linkEdit.getFileOffset());
		}
		for (int i = 0; i < splitDyldCache.size(); i++) {
			DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(i);
			for (DyldCacheMappingInfo mappingInfo : dyldCacheHeader.getMappingInfos()) {
				if (mappingInfo.contains(linkEdit.getVMaddress())) {
					BinaryReader linkEditReader =
						new BinaryReader(splitDyldCache.getProvider(i), true);
					linkEditReader.setPointerIndex(linkEdit.getFileOffset());
					return linkEditReader;
				}
			}
		}
		throw new MachException("__LINKEDIT segment not found in DYLD cache");
	}
}
