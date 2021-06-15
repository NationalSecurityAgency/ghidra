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
package db;

import java.io.IOException;

public class TranslatedRecordIterator implements RecordIterator {
	private RecordIterator it;
	private RecordTranslator translator;
	
	public TranslatedRecordIterator(RecordIterator it, RecordTranslator translator) {
		this.it = it;
		this.translator = translator;
	}
	
	@Override
	public boolean hasNext() throws IOException {
		return it.hasNext();
	}

	@Override
	public boolean hasPrevious() throws IOException {
		return it.hasPrevious();
	}

	@Override
	public DBRecord next() throws IOException {
		return translator.translateRecord(it.next());
	}
	
	@Override
	public DBRecord previous() throws IOException {
		return translator.translateRecord(it.previous());
	}
	
	@Override
	public boolean delete() throws IOException {
		throw new UnsupportedOperationException();
	}
}

