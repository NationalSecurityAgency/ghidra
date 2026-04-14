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
package ghidra.program.database.bookmark;

import java.util.*;

/**
 * Class for managing bookmark type objects. This object is immutable so that multiple threads
 * can read from it. When a new type is added, a BookmarkTypes object is created within a 
 * synchronized call
 */
class BookmarkTypes {
	private Map<String, BookmarkTypeDB> nameToTypeMap = new HashMap<>();
	private Map<Integer, BookmarkTypeDB> idToTypeMap = new HashMap<>();
	private List<BookmarkTypeDB> bookmarkList = new ArrayList<>();

	void addBookmarkType(BookmarkTypeDB bookmarkType) {
		bookmarkList.add(bookmarkType);
		nameToTypeMap.put(bookmarkType.getTypeString(), bookmarkType);
		idToTypeMap.put(bookmarkType.getTypeId(), bookmarkType);
		Collections.sort(bookmarkList, (t1, t2) -> Integer.compare(t1.getTypeId(), t2.getTypeId()));
	}

	/**
	 * {@return all the bookmark types in a random order}
	 */
	Collection<BookmarkTypeDB> getAllTypes() {
		return bookmarkList;
	}

	/**
	 * Returns the bookmark type for the given type name or null if no bookmark type exists with
	 * that name.
	 * @param typeName the name of the bookmark type to get
	 * @return  the bookmark type for the given type name or null if it doesn't exist
	 */
	BookmarkTypeDB get(String typeName) {
		return nameToTypeMap.get(typeName);
	}

	/**
	 * Returns the bookmark type with the given id.
	 * @param typeId the id to get the bookmark type for
	 * @return the bookmark type with the given id
	 */
	BookmarkTypeDB getTypeById(int typeId) {
		return idToTypeMap.get(typeId);
	}

	/**
	 * {@return the lowest id that doesn't have a corresponding bookmark type}
	 */
	int getLowestUnusedId() {
		for (int i = 0; i < bookmarkList.size(); i++) {
			if (bookmarkList.get(i).getTypeId() != i) {
				return i;
			}
		}
		return bookmarkList.size();
	}

}
