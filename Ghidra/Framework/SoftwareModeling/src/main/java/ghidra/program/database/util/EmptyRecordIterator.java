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
/*
 *
 */
package ghidra.program.database.util;

import java.io.IOException;

import db.DBRecord;
import db.RecordIterator;

/**
 * Implementation of a RecordIterator that is always empty.
 */
public class EmptyRecordIterator implements RecordIterator {

	/**
	 * @see db.RecordIterator#hasNext()
	 */
	public boolean hasNext() throws IOException {
		return false;
	}

	/**
	 * @see db.RecordIterator#hasPrevious()
	 */
	public boolean hasPrevious() throws IOException {
		return false;
	}

	/**
	 * @see db.RecordIterator#next()
	 */
	public DBRecord next() throws IOException {
		return null;
	}

	/**
	 * @see db.RecordIterator#previous()
	 */
	public DBRecord previous() throws IOException {
		return null;
	}

	/**
	 * @see db.RecordIterator#delete()
	 */
	public boolean delete() throws IOException {
		return false;
	}

}
