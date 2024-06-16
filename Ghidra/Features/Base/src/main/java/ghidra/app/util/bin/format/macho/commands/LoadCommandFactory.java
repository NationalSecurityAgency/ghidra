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
		long origIndex = reader.getPointerIndex();
		int type = reader.peekNextInt();
		try {
			return switch (type) {
				case LC_SEGMENT:
					yield new SegmentCommand(reader, header.is32bit());
				case LC_SYMTAB:
					yield new SymbolTableCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache), header);
				case LC_SYMSEG:
					yield new SymbolCommand(reader);
				case LC_THREAD:
				case LC_UNIXTHREAD:
					yield new ThreadCommand(reader, header);
				case LC_LOADFVMLIB:
				case LC_IDFVMLIB:
					yield new FixedVirtualMemorySharedLibraryCommand(reader);
				case LC_IDENT:
					yield new IdentCommand(reader);
				case LC_FVMFILE:
					yield new FixedVirtualMemoryFileCommand(reader);
				case LC_PREPAGE:
					yield new UnsupportedLoadCommand(reader);
				case LC_DYSYMTAB:
					yield new DynamicSymbolTableCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache), header);
				case LC_LOAD_DYLIB:
				case LC_ID_DYLIB:
				case LC_LOAD_UPWARD_DYLIB:
					yield new DynamicLibraryCommand(reader);
				case LC_LOAD_DYLINKER:
				case LC_ID_DYLINKER:
				case LC_DYLD_ENVIRONMENT:
					yield new DynamicLinkerCommand(reader);
				case LC_PREBOUND_DYLIB:
					yield new PreboundDynamicLibraryCommand(reader);
				case LC_ROUTINES:
					yield new RoutinesCommand(reader, header.is32bit());
				case LC_SUB_FRAMEWORK:
					yield new SubFrameworkCommand(reader);
				case LC_SUB_UMBRELLA:
					yield new SubUmbrellaCommand(reader);
				case LC_SUB_CLIENT:
					yield new SubClientCommand(reader);
				case LC_SUB_LIBRARY:
					yield new SubLibraryCommand(reader);
				case LC_TWOLEVEL_HINTS:
					yield new TwoLevelHintsCommand(reader);
				case LC_PREBIND_CKSUM:
					yield new PrebindChecksumCommand(reader);
				case LC_LOAD_WEAK_DYLIB:
					yield new DynamicLibraryCommand(reader);
				case LC_SEGMENT_64:
					yield new SegmentCommand(reader, header.is32bit());
				case LC_ROUTINES_64:
					yield new RoutinesCommand(reader, header.is32bit());
				case LC_UUID:
					yield new UuidCommand(reader);
				case LC_RPATH:
					yield new RunPathCommand(reader);
				case LC_CODE_SIGNATURE:
					yield new CodeSignatureCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_SEGMENT_SPLIT_INFO:
				case LC_OPTIMIZATION_HINT:
				case LC_DYLIB_CODE_SIGN_DRS:
					yield new LinkEditDataCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_REEXPORT_DYLIB:
					yield new DynamicLibraryCommand(reader);
				case LC_ENCRYPTION_INFO:
				case LC_ENCRYPTION_INFO_64:
					yield new EncryptedInformationCommand(reader, header.is32bit());
				case LC_DYLD_INFO:
				case LC_DYLD_INFO_ONLY:
					yield new DyldInfoCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache), header);
				case LC_VERSION_MIN_MACOSX:
				case LC_VERSION_MIN_IPHONEOS:
				case LC_VERSION_MIN_TVOS:
				case LC_VERSION_MIN_WATCHOS:
					yield new VersionMinCommand(reader);
				case LC_FUNCTION_STARTS:
					yield new FunctionStartsCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_MAIN:
					yield new EntryPointCommand(reader);
				case LC_DATA_IN_CODE:
					yield new DataInCodeCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_SOURCE_VERSION:
					yield new SourceVersionCommand(reader);
				case LC_LAZY_LOAD_DYLIB:
					yield new DynamicLibraryCommand(reader);
				case LC_LINKER_OPTIONS:
					yield new LinkerOptionCommand(reader);
				case LC_BUILD_VERSION:
					yield new BuildVersionCommand(reader);
				case LC_DYLD_EXPORTS_TRIE:
					yield new DyldExportsTrieCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_DYLD_CHAINED_FIXUPS:
					yield new DyldChainedFixupsCommand(reader,
						getLinkerLoadCommandReader(reader, header, splitDyldCache));
				case LC_FILESET_ENTRY:
					yield new FileSetEntryCommand(reader);
				default:
					yield new UnsupportedLoadCommand(reader);
			};
		}
		catch (Exception e) {
			reader.setPointerIndex(origIndex);
			return new CorruptLoadCommand(reader, e);
		}
	}

	/**
	 * Gets a {@link BinaryReader} capable of reading the load commands used by the dynamic linker.
	 * In the case of the DYLD cache, these load commands will reside in the __LINKEDIT segment,
	 * which could be in a different provider than the Mach-O header if a {@link SplitDyldCache} 
	 * is being used.
	 * <p>
	 * NOTE: This method assumes that all of the segment {@link LoadCommand}s have already been
	 * parsed.
	 * 
	 * @param reader The {@link BinaryReader} used to read the given Mach-O header
	 * @param header The {@link MachHeader Mach-O header}
	 * @param splitDyldCache The {@link SplitDyldCache}, or null if that is not being used
	 * @return A {@link BinaryReader} capable of reading the load commands used by the dynamic
	 *   linker.  Nothing should be assumed about where this reader initially points to.
	 * @throws MachException If the __LINKEDIT segment was expected but not found
	 */
	private static BinaryReader getLinkerLoadCommandReader(BinaryReader reader, MachHeader header,
			SplitDyldCache splitDyldCache) throws MachException {
		if (splitDyldCache == null) {
			return reader.clone();
		}
		SegmentCommand linkEdit = header.getSegment(SegmentNames.SEG_LINKEDIT);
		if (linkEdit != null) {
			for (int i = 0; i < splitDyldCache.size(); i++) {
				DyldCacheHeader dyldCacheHeader = splitDyldCache.getDyldCacheHeader(i);
				for (DyldCacheMappingInfo mappingInfo : dyldCacheHeader.getMappingInfos()) {
					if (mappingInfo.contains(linkEdit.getVMaddress())) {
						return new BinaryReader(splitDyldCache.getProvider(i), true);
					}
				}
			}
		}
		throw new MachException("__LINKEDIT segment not found in DYLD cache");
	}
}
