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
package ghidra.app.util.bin.format.elf.info;

import java.io.IOException;

import ghidra.app.util.bin.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

/**
 * Interface and helper functions to read and markup things that have been read from an
 * Elf program.
 */
public interface ElfInfoItem {

	/**
	 * Markup a program's info and memory with this item.
	 * 
	 * @param program {@link Program} to markup
	 * @param address {@link Address} of the item in the program
	 */
	void markupProgram(Program program, Address address);

	public record ItemWithAddress<T>(T item, Address address) {}

	public interface ReaderFunc<T> {
		T read(BinaryReader br, Program program) throws IOException;
	}

	/**
	 * Helper method to markup a program if it contains the specified item in the specified
	 * memory section.
	 *  
	 * @param program {@link Program}
	 * @param sectionName name of memory section that contains the item
	 * @param readFunc {@link ReaderFunc} that will deserialize an instance of the item
	 */
	static void markupElfInfoItemSection(Program program, String sectionName,
			ReaderFunc<ElfInfoItem> readFunc) {
		ItemWithAddress<ElfInfoItem> wrappedItem =
			readItemFromSection(program, sectionName, readFunc);
		if (wrappedItem != null) {
			wrappedItem.item().markupProgram(program, wrappedItem.address());
		}
	}

	/**
	 * Helper method to read an item from a program's memory section.
	 * 
	 * @param <T> type of the item that will be read
	 * @param program {@link Program} to read from
	 * @param sectionName name of memory section that contains the item
	 * @param readFunc {@link ReaderFunc} that will deserialize an instance of the item
	 * @return a wrapped instance of the item, or null if the memory section does not exist
	 * or there was an error while reading the item from the section
	 */
	static <T extends ElfInfoItem> ItemWithAddress<T> readItemFromSection(Program program,
			String sectionName, ReaderFunc<T> readFunc) {
		return readItemFromSection(program, program.getMemory().getBlock(sectionName), readFunc);
	}

	static <T extends ElfInfoItem> ItemWithAddress<T> readItemFromSection(Program program,
			MemoryBlock memBlock, ReaderFunc<T> readFunc) {
		if (memBlock != null) {
			try (ByteProvider bp =
				MemoryByteProvider.createMemoryBlockByteProvider(program.getMemory(), memBlock)) {
				BinaryReader br = new BinaryReader(bp, !program.getMemory().isBigEndian());

				T item = readFunc.read(br, program);
				return item != null ? new ItemWithAddress<>(item, memBlock.getStart()) : null;
			}
			catch (IOException e) {
				Msg.warn(ElfInfoItem.class,
					"Unable to read Elf item in section: %s".formatted(memBlock.getName()), e);
			}
		}
		return null;
	}
}
