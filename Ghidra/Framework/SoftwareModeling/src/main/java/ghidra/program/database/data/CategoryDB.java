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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import db.DBRecord;
import db.Field;
import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.util.InvalidNameException;
import ghidra.util.Lock;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;

/**
 * Database implementation for Category.
 */
class CategoryDB extends DatabaseObject implements Category {

	private DataTypeManagerDB mgr;
	private volatile CategoryDB parent;
	private volatile String name;

	private LazyLoadingCachingMap<String, CategoryDB> subcategoryMap;
	private LazyLoadingCachingMap<String, DataType> dataTypeMap;
	private ConflictMap conflictMap;
	private CategoryPath categoryPath;

	/**
	 * Category Constructor
	 * @param dtMgr the data type manager
	 * @param cache CategoryDB object cache
	 * @param id the id for this category
	 * @param parent the parent for this category
	 * @param name the name of this category
	 */
	CategoryDB(DataTypeManagerDB dtMgr, DBObjectCache<CategoryDB> cache, long id, CategoryDB parent,
			String name) {
		super(cache, id);
		this.mgr = dtMgr;
		this.name = name;
		this.parent = parent;

		subcategoryMap = new LazyLoadingCachingMap<>(mgr.lock) {
			@Override
			public Map<String, CategoryDB> loadMap() {
				return buildSubcategoryMap();
			}
		};
		dataTypeMap = new LazyLoadingCachingMap<>(mgr.lock) {
			@Override
			public Map<String, DataType> loadMap() {
				return createDataTypeMap();
			}
		};
		conflictMap = new ConflictMap(mgr.lock);
	}

	/**
	 * Root Category Constructor
	 * @param dtMgr the data type manager
	 * @param cache CategoryDB object cache
	 */
	CategoryDB(DataTypeManagerDB dtMgr, DBObjectCache<CategoryDB> cache) {
		this(dtMgr, cache, DataTypeManagerDB.ROOT_CATEGORY_ID, null, "/");
	}

	@Override
	public CategoryPath getCategoryPath() {
		CategoryPath localCategoryPath = categoryPath;
		if (localCategoryPath != null && !isInvalid()) {
			return localCategoryPath;
		}
		mgr.lock.acquire();
		try {
			if (!checkIsValid() || isRoot()) {
				categoryPath = CategoryPath.ROOT;
			}
			if (categoryPath == null) {
				categoryPath = new CategoryPath(parent.getCategoryPath(), name);
			}
			return categoryPath;
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	protected boolean refresh() {
		return refresh(null);
	}

	@Override
	protected boolean refresh(DBRecord rec) {
		subcategoryMap.clear();
		dataTypeMap.clear();
		conflictMap.clear();
		categoryPath = null;

		if (isRoot()) {
			return true;
		}
		try {
			if (rec == null) {
				rec = mgr.getCategoryDBAdapter().getRecord(key);
			}
			if (rec == null) {
				return false;
			}
			this.parent =
				mgr.getCategoryDB(rec.getLongValue(CategoryDBAdapter.CATEGORY_PARENT_COL));
			this.name = rec.getString(CategoryDBAdapter.CATEGORY_NAME_COL);
		}
		catch (IOException e) {
			mgr.dbError(e);
		}
		return true;
	}

	/**
	 * @see ghidra.program.model.data.Category#getName()
	 */
	@Override
	public String getName() {
		validate(mgr.lock);
		if (isRoot()) {
			return mgr.getName();
		}
		return name;
	}

	/**
	 * @see ghidra.program.model.data.Category#setName(java.lang.String)
	 */
	@Override
	public void setName(String newName) throws InvalidNameException, DuplicateNameException {
		testName(newName);
		mgr.lock.acquire();
		try {
			checkDeleted();
			CategoryPath oldPath = getCategoryPath();
			if (isRoot()) {
				mgr.setName(newName);
				return;
			}
			if (newName.equals(name)) {
				return;
			}
			if (parent.getCategory(newName) != null) {
				throw new DuplicateNameException("Category named " + newName + " already exists");
			}
			String oldName = name;
			name = newName;
			try {
				mgr.getCategoryDBAdapter().updateRecord(key, parent.key, newName);
			}
			catch (IOException e) {
				mgr.dbError(e);
			}
			parent.catagoryRenamed(this, oldName);
			mgr.categoryRenamed(oldPath, this);
		}
		finally {
			mgr.lock.release();
		}
	}

	private CategoryDB[] getCategories(long parentId) {
		try {
			Field[] ids = mgr.getCategoryDBAdapter().getRecordIdsWithParent(parentId);
			CategoryDB[] cats = new CategoryDB[ids.length];
			for (int i = 0; i < cats.length; i++) {
				cats[i] = mgr.getCategoryDB(ids[i].getLongValue());
			}
			return cats;
		}
		catch (IOException e) {
			mgr.dbError(e);
			return null;
		}
	}

	private Map<String, CategoryDB> buildSubcategoryMap() {
		CategoryDB[] categories = getCategories(key);
		Map<String, CategoryDB> map = new ConcurrentHashMap<>(2 * categories.length);
		for (CategoryDB category : categories) {
			map.put(category.getName(), category);
		}
		return map;
	}

	private Map<String, DataType> createDataTypeMap() {
		List<DataType> dataTypeList = mgr.getDataTypesInCategory(key);
		Map<String, DataType> map = new ConcurrentHashMap<>(2 * dataTypeList.size());
		for (DataType dataType : dataTypeList) {
			map.put(dataType.getName(), dataType);
		}
		return map;
	}

	private String getBaseName(String dataTypeName) {
		int indexOf = dataTypeName.indexOf(DataType.CONFLICT_SUFFIX);
		if (indexOf <= 0) {
			return dataTypeName;
		}
		return dataTypeName.substring(0, indexOf);
	}

	private boolean isConflictName(String dataTypeName) {
		return dataTypeName.contains(DataType.CONFLICT_SUFFIX);
	}

	/**
	 * @see ghidra.program.model.data.Category#getCategories()
	 */
	@Override
	public Category[] getCategories() {
		validate(mgr.lock);
		Collection<CategoryDB> categories = subcategoryMap.values();
		return categories.toArray(new Category[categories.size()]);
	}

	/**
	 * @see ghidra.program.model.data.Category#getDataTypes()
	 */
	@Override
	public DataType[] getDataTypes() {
		validate(mgr.lock);
		Collection<DataType> dataTypes = dataTypeMap.values();
		return dataTypes.toArray(new DataType[dataTypes.size()]);
	}

	/**
	 * @see ghidra.program.model.data.Category#addDataType(ghidra.program.model.data.DataType, ghidra.program.model.data.DataTypeConflictHandler)
	 */
	@Override
	public DataType addDataType(DataType dt, DataTypeConflictHandler handler) {
		mgr.lock.acquire();
		try {
			checkDeleted();
			if (!getCategoryPath().equals(dt.getCategoryPath())) {
				dt = dt.clone(dt.getDataTypeManager());
				try {
					dt.setCategoryPath(getCategoryPath());
				}
				catch (DuplicateNameException e) {
					// can't happen here because we made a copy
				}
			}
			DataType resolvedDataType = mgr.resolve(dt, handler);
			return resolvedDataType;
		}
		finally {
			mgr.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Category#getCategory(java.lang.String)
	 */
	@Override
	public CategoryDB getCategory(String subcategoryName) {
		validate(mgr.lock);
		return subcategoryMap.get(subcategoryName);
	}

	/**
	 * @see ghidra.program.model.data.Category#getDataType(java.lang.String)
	 */
	@Override
	public DataType getDataType(String dataTypeName) {
		validate(mgr.lock);
		return dataTypeMap.get(dataTypeName);
	}

	private void testName(String categoryName) throws InvalidNameException {
		if (categoryName == null || categoryName.length() == 0) {
			throw new InvalidNameException("Name cannot be null or zero length");
		}
	}

	/**
	 * @see ghidra.program.model.data.Category#createCategory(java.lang.String)
	 */
	@Override
	public Category createCategory(String categoryName) throws InvalidNameException {
		testName(categoryName);
		mgr.lock.acquire();
		try {
			checkDeleted();
			CategoryDB cat = mgr.createCategoryDB(this, categoryName);
			return cat;
		}
		catch (IOException e1) {
			mgr.dbError(e1);
		}
		finally {
			mgr.lock.release();
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.data.Category#removeCategory(java.lang.String, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean removeCategory(String categoryName, TaskMonitor monitor) {
		mgr.lock.acquire();
		try {
			checkDeleted();
			CategoryDB c = getCategory(categoryName);
			if (c == null) {
				return false;
			}
			Category[] cats = c.getCategories();
			for (Category cat : cats) {
				if (monitor.isCancelled()) {
					return false;
				}
				c.removeCategory(cat.getName(), monitor);
			}
			DataType[] dts = c.getDataTypes();
			for (DataType dt : dts) {
				if (monitor.isCancelled()) {
					return false;
				}
				mgr.remove(dt, monitor);
			}
			try {
				mgr.getCategoryDBAdapter().removeCategory(c.getKey());
				subcategoryMap.remove(categoryName);
				mgr.categoryRemoved(this, categoryName, c.getKey());
				return true;
			}
			catch (IOException e) {
				mgr.dbError(e);
			}
			return false;
		}
		finally {
			mgr.lock.release();
		}
	}

	@Override
	public boolean removeEmptyCategory(String categoryName, TaskMonitor monitor) {
		mgr.lock.acquire();
		try {
			checkDeleted();
			CategoryDB c = getCategory(categoryName);
			if (c == null) {
				return false;
			}
			Category[] cats = c.getCategories();
			DataType[] dts = c.getDataTypes();
			if (cats.length != 0 || dts.length != 0) {
				return false;
			}
			try {
				mgr.getCategoryDBAdapter().removeCategory(c.getKey());
				subcategoryMap.remove(categoryName);
				mgr.categoryRemoved(this, categoryName, c.getKey());
				return true;
			}
			catch (IOException e) {
				mgr.dbError(e);
			}
			return false;
		}
		finally {
			mgr.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Category#moveCategory(ghidra.program.model.data.Category, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public void moveCategory(Category category, TaskMonitor monitor) throws DuplicateNameException {
		if (mgr != category.getDataTypeManager()) {
			throw new IllegalArgumentException("Category does not belong to my DataTypeManager");
		}
		if (!(category instanceof CategoryDB)) {
			throw new IllegalArgumentException("Category is not a CategoryDB");
		}
		CategoryDB categoryDB = (CategoryDB) category;
		mgr.lock.acquire();
		try {
			checkDeleted();
			if (getCategory(categoryDB.getName()) != null) {
				throw new DuplicateNameException(
					"Category named " + categoryDB.getName() + " already exists");
			}
			CategoryPath destCategoryPath = getCategoryPath();
			CategoryPath movedCategoryOriginalPath = categoryDB.getCategoryPath();
			if (destCategoryPath.isAncestorOrSelf(movedCategoryOriginalPath)) {
				throw new IllegalArgumentException(
					"Moved category is an ancestor of destination category!");
			}
			try {
				categoryDB.setParent(this);
			}
			catch (IOException e) {
				mgr.dbError(e);
			}
			subcategoryMap.put(categoryDB.getName(), categoryDB);
			mgr.categoryMoved(movedCategoryOriginalPath, categoryDB);
		}
		finally {
			mgr.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Category#copyCategory(ghidra.program.model.data.Category, ghidra.program.model.data.DataTypeConflictHandler, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public Category copyCategory(Category category, DataTypeConflictHandler handler,
			TaskMonitor monitor) {
		// TODO: source archive handling is not documented
		boolean isInSameArchive = (mgr == category.getDataTypeManager());
		mgr.lock.acquire();
		try {
			checkDeleted();
			Category cat = createCategory(category.getName());
			Category[] cats = category.getCategories();
			for (Category cat2 : cats) {
				if (monitor.isCancelled()) {
					return cat;
				}
				cat.copyCategory(cat2, handler, monitor);
			}
			DataType[] dts = category.getDataTypes();
			for (DataType dt : dts) {
				if (monitor.isCancelled()) {
					break;
				}
				DataType newDataType = isInSameArchive ? dt.copy(mgr) : dt.clone(mgr);
				cat.addDataType(newDataType, handler);
			}
			return cat;
		}
		catch (InvalidNameException e) {
			// can't happen--already had a valid name
		}
		finally {
			mgr.lock.release();
		}
		return null;
	}

	/**
	 * @see ghidra.program.model.data.Category#getParent()
	 */
	@Override
	public Category getParent() {
		validate(mgr.lock);
		return parent;
	}

	/**
	 * @see ghidra.program.model.data.Category#isRoot()
	 */
	@Override
	public boolean isRoot() {
		return parent == null;
	}

	/**
	 * Get the fully qualified name for this category.
	 */
	@Override
	public String getCategoryPathName() {
		CategoryPath path = getCategoryPath();
		return path.getPath();
	}

	/**
	 * Get the root category.
	 */
	@Override
	public Category getRoot() {
		return mgr.getCategory(DataTypeManagerDB.ROOT_CATEGORY_ID);
	}

	/**
	 * @see ghidra.program.model.data.Category#getID()
	 */
	@Override
	public long getID() {
		return getKey();
	}

	/**
	 * Get the data type manager associated with this category.
	 */
	@Override
	public DataTypeManager getDataTypeManager() {
		return mgr;
	}

	/**
	 * @see ghidra.program.model.data.Category#moveDataType(ghidra.program.model.data.DataType, ghidra.program.model.data.DataTypeConflictHandler)
	 */
	@Override
	public void moveDataType(DataType movedDataType, DataTypeConflictHandler handler)
			throws DataTypeDependencyException {
		mgr.lock.acquire();
		try {
			checkDeleted();
			CategoryPath path = getCategoryPath();
			if (handler == null) {
				handler = DataTypeConflictHandler.DEFAULT_HANDLER;
			}
			if (movedDataType.getDataTypeManager() != mgr) {
				throw new IllegalArgumentException("Given dataType not in this data type manager");
			}
			DataType existing = getDataType(movedDataType.getName());
			if (movedDataType == existing) {
				return;
			}
			if (existing != null) {
				ConflictResult result = mgr.resolveConflict(handler, movedDataType, existing);
				if (result == ConflictResult.REPLACE_EXISTING) { // replace existing dt with new dt.
					mgr.replaceDataType(existing, movedDataType, true);
				}
				else if (result == ConflictResult.USE_EXISTING) {
					mgr.replaceDataType(movedDataType, existing, false);
				}
				else { // both dataTypes remain
					movedDataType.setNameAndCategory(path,
						mgr.getUnusedConflictName(path, movedDataType.getName()));
				}
			}
			else {
				movedDataType.setCategoryPath(path);
			}
		}
		catch (InvalidNameException e) {
			throw new AssertException(e); // can't happen
		}
		catch (DuplicateNameException e) {
			throw new AssertException(e); // can't happen?
		}
		finally {
			mgr.lock.release();
		}
	}

	/**
	 * @see ghidra.program.model.data.Category#remove(ghidra.program.model.data.DataType, ghidra.util.task.TaskMonitor)
	 */
	@Override
	public boolean remove(DataType type, TaskMonitor monitor) {
		CategoryPath path = getCategoryPath();
		if (type.getDataTypeManager() != this.mgr || !type.getCategoryPath().equals(path)) {
			throw new IllegalArgumentException(
				"can't remove dataType from category that its not a member of!");
		}
		return mgr.remove(type, monitor);
	}

	/**
	 * @see java.lang.Comparable#compareTo(java.lang.Object)
	 */
	@Override
	public int compareTo(Category otherCategory) {
		CategoryPath path = getCategoryPath();
		return path.compareTo(otherCategory.getCategoryPath());
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString() {
		CategoryPath path = getCategoryPath();

		return mgr.getName() + path.toString();
	}

	private void setParent(CategoryDB newParent) throws IOException {
		mgr.getCategoryDBAdapter().updateRecord(key, newParent.key, name);
		if (parent == null) {
			throw new AssertException("Should not be able to reparent root!");
		}
		parent.subcategoryMap.remove(name);
		parent = newParent;
	}

	private void catagoryRenamed(CategoryDB childCategory, String oldName) {
		subcategoryMap.remove(oldName);
		subcategoryMap.put(childCategory.getName(), childCategory);
	}

	void dataTypeRenamed(DataType childDataType, String oldName) {
		dataTypeRemoved(oldName);
		dataTypeAdded(childDataType);
	}

	void dataTypeAdded(DataType dataType) {
		String dtName = dataType.getName();
		dataTypeMap.put(dtName, dataType);
		if (isConflictName(dtName)) {
			conflictMap.addDataType(dataType);
		}
	}

	void dataTypeRemoved(String dataTypeName) {
		dataTypeMap.remove(dataTypeName);
		if (isConflictName(dataTypeName)) {
			conflictMap.removeDataTypeName(dataTypeName);
		}
	}

	void categoryAdded(CategoryDB cat) {
		subcategoryMap.put(cat.getName(), cat);
	}

	@Override
	public List<DataType> getDataTypesByBaseName(String dataTypeName) {
		List<DataType> list = new ArrayList<>();
		String baseName = getBaseName(dataTypeName);

		DataType baseType = dataTypeMap.get(baseName);
		if (baseType != null) {
			list.add(baseType);
		}

		List<DataType> relatedNameDataTypes = conflictMap.getDataTypesByBaseName(baseName);
		list.addAll(relatedNameDataTypes);
		return list;
	}

	/**
	 * Class to handle the complexities of having a map as the value in a LazyLoadingCachingMap
	 * This map uses the data type's base name as the key (i.e. all .conflict suffixes stripped off.)
	 * The value is another map that maps the actual data type's name to the data type. This map
	 * effectively provides an efficient way to get all data types in a category that have the
	 * same name, but possibly have had their name modified (by appending .conflict) to get around
	 * the requirement that names have to be unique in the same category.
	 */
	private class ConflictMap extends LazyLoadingCachingMap<String, Map<String, DataType>> {

		ConflictMap(Lock lock) {
			super(lock);
		}

		/**
		 * Creates a map of all data types whose name has a .conflict suffix where the key
		 * is the base name and {@link LazyLoadingCachingMap} the value is a map of actual name 
		 * to data type. This mapping is
		 * maintained as a lazy cache map. This is only called by the super class when the
		 * cached needs to be populated and we are depending on it to acquire the necessary
		 * database lock. (See {@link LazyLoadingCachingMap#loadMap()}
		 * @return the loaded map
		 */
		@Override
		protected Map<String, Map<String, DataType>> loadMap() {
			Map<String, Map<String, DataType>> map = new HashMap<>();
			Collection<DataType> values = dataTypeMap.values();
			for (DataType dataType : values) {
				String dataTypeName = dataType.getName();
				if (isConflictName(dataTypeName)) {
					String baseName = getBaseName(dataTypeName);
					Map<String, DataType> innerMap =
						map.computeIfAbsent(baseName, b -> new HashMap<>());
					innerMap.put(dataTypeName, dataType);
				}
			}
			return map;
		}

		/**
		 * Adds the data type to the conflict mapping structure. If the mapping is currently not
		 * loaded then this method can safely do nothing. This method is synchronized to provide
		 * thread safe access/manipulation of the map.
		 * @param dataType the data type to add to the mapping if the mapping is already loaded
		 */
		synchronized void addDataType(DataType dataType) {
			// if the cache is not currently populated, don't need to do anything
			Map<String, Map<String, DataType>> map = getMap();
			if (map == null) {
				return;
			}

			String dataTypeName = dataType.getName();
			String baseName = getBaseName(dataTypeName);
			Map<String, DataType> innerMap = map.computeIfAbsent(baseName, b -> new HashMap<>());
			innerMap.put(dataTypeName, dataType);
		}

		/**
		 * Removes the data type with the given name from the conflict mapping structure. If the 
		 * mapping is currently not loaded then this method can safely do nothing. This method is
		 * synchronized to provide thread safe access/manipulate of the map.
		 * @param dataTypeName the name of the data type  to remove from this mapping
		 */
		synchronized void removeDataTypeName(String dataTypeName) {
			Map<String, Map<String, DataType>> map = getMap();
			if (map == null) {
				return;
			}
			String baseName = getBaseName(dataTypeName);
			Map<String, DataType> innerMap = map.get(baseName);
			if (innerMap == null) {
				return;
			}
			innerMap.remove(dataTypeName);
		}

		/**
		 * Returns a list of all data types that have conflict names for the given base name
		 * @param baseName the data type base name to search for (i.e. the .conflict suffix removed)
		 * @return a list of all conflict named data types that would have the given base name if
		 * no conflicts existed
		 */
		List<DataType> getDataTypesByBaseName(String baseName) {

			// Note that the following call to get MUST NOT be in a synchronized block because
			// it may trigger a loading of the cache which requires a database lock and you
			// can't be synchronized on this class when acquiring a database lock or else a
			// deadlock will occur.
			Map<String, DataType> map = get(baseName);
			if (map == null) {
				return Collections.emptyList();
			}

			// the following must be synchronized so that the implied iterator can complete without
			// another thread changing the map's values.
			synchronized (this) {
				return new ArrayList<>(map.values());
			}
		}

	}
}
