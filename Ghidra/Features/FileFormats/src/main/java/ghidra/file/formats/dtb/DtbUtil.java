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
package ghidra.file.formats.dtb;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;

public final class DtbUtil {

	/**
	 * Returns TRUE if the program is using the DATA Big-Endian language.
	 * @param program the program to check language.
	 * @param log the message log to report errors.
	 * @return TRUE if the program is using the DATA Big-Endian language
	 */
	public final static boolean isCorrectProcessor(Program program, MessageLog log) {
		Language language = program.getLanguage();
		if (language.getProcessor() == Processor.findOrPossiblyCreateProcessor("DATA") &&
			language.isBigEndian()) {
			return true;
		}
		log.appendMsg(program.getName() + " must use \"Data Big-Endian\" processor module.");
		return false;
	}

	/**
	 * Returns TRUE if the program is loaded using Binary Loader.
	 * @param program the program to check loader.
	 * @return TRUE if the program is loaded using Binary Loader
	 */
	public final static boolean isCorrectLoader(Program program) {
		return BinaryLoader.BINARY_NAME.equals(program.getExecutableFormat());
	}
}
