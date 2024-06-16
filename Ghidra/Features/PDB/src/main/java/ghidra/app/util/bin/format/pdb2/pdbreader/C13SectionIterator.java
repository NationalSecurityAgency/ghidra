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
package ghidra.app.util.bin.format.pdb2.pdbreader;

import java.util.NoSuchElementException;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Iterator for {@link C13Section} data being read from C13 section of module stream.
 * @param <T> the iterator type
 */
class C13SectionIterator<T extends C13Section> implements ParsingIterator<T> {

	private PdbByteReader reader;
	private Class<T> clazz;
	private boolean processIgnore;
	private TaskMonitor monitor;

	private C13Type requestedType;

	private C13Type detectedType; // section type detected
	private T currentSection = null;

	/**
	 * An Iterator of C13 Section types
	 * @param reader PdbByteReader containing only C13 Section information and in newly
	 * constructed state
	 * @param clazz the class of the iterator type
	 * @param processIgnore processes records marked as ignore
	 * @param monitor {@link TaskMonitor} used for checking user cancellation
	 * @throws CancelledException upon user cancellation
	 */
	public C13SectionIterator(PdbByteReader reader, Class<T> clazz, boolean processIgnore,
			TaskMonitor monitor) throws CancelledException {
		this.reader = reader;
		this.clazz = clazz;
		this.requestedType = C13Type.fromClassValue(clazz);
		this.processIgnore = processIgnore;
		this.monitor = monitor;
	}

	@Override
	public boolean hasNext() throws CancelledException {
		if (currentSection == null) {
			find();
		}
		return (currentSection != null);
	}

	@Override
	public T next() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			T returnSection = currentSection;
			currentSection = null;
			return returnSection;
		}
		throw new NoSuchElementException("next() called with no more elements");
	}

	@Override
	public T peek() throws CancelledException, NoSuchElementException {
		if (hasNext()) {
			return currentSection;
		}
		throw new NoSuchElementException("peek() called with no more elements");
	}

	private void find() throws CancelledException {
		try {
			currentSection = findAndParse();
		}
		catch (PdbException e) {
			Msg.error(this, "Problem seen in find()", e);
			currentSection = null;
		}
	}

	/**
	 * Finds and parses the next C13 Section type requested
	 * @return the found and parsed element. Can be null if not found
	 * @throws CancelledException upon user cancellation
	 * @throws PdbException upon problem parsing data
	 */
	public T findAndParse() throws CancelledException, PdbException {
		while (reader.hasMore()) {
			monitor.checkCancelled();
			int index = reader.getIndex();
			int typeVal = reader.parseInt();
			boolean ignore = C13Type.ignore(typeVal);
			detectedType = C13Type.fromValue(typeVal);
			int len = reader.parseInt();
			if ((!ignore || processIgnore) &&
				(requestedType == C13Type.ALL || detectedType == requestedType)) {
				reader.setIndex(index);
				C13Section parsedSection = C13Section.parse(reader, monitor);
				return (parsedSection.getClass().equals(clazz) ||
					C13Section.class.equals(clazz))
							? clazz.cast(parsedSection)
							: null;
			}
			reader.skip(len);
		}
		return null;
	}

}
