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

import java.util.List;

import ghidra.app.util.bin.format.elf.ElfLoadHelper;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Something that adds nice-to-have markup and program info to Elf binaries.
 * <p>
 * Classes that implement this ExtensionPoint must have names that end with "ElfInfoProducer" for
 * the class searcher to find them.
 * <p>
 * Instances are created for each Elf binary that is being loaded.
 */
public interface ElfInfoProducer extends ExtensionPoint {

	/**
	 * Returns a sorted list of new and initialized ElfInfoProducer instances. 
	 * 
	 * @param elfLoadHelper {@link ElfLoadHelper} with contents of file being loaded
	 * @return List of ElfInfoProducers
	 */
	public static List<ElfInfoProducer> getElfInfoProducers(ElfLoadHelper elfLoadHelper) {
		List<ElfInfoProducer> result = ClassSearcher.getInstances(ElfInfoProducer.class);
		for (ElfInfoProducer eip : result) {
			eip.init(elfLoadHelper);
		}
		return result;
	}

	/**
	 * Initializes this instance.
	 * 
	 * @param elfLoadHelper the Elf binary
	 */
	void init(ElfLoadHelper elfLoadHelper);

	/**
	 * Called by the Elf loader to give this ElfInfoProducer the opportunity to markup the Elf
	 * binary.
	 * 
	 * @param monitor {@link TaskMonitor}
	 */
	void markupElfInfo(TaskMonitor monitor) throws CancelledException;
}
