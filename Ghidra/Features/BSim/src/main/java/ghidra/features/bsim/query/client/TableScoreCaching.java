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
package ghidra.features.bsim.query.client;

import java.sql.Types;
import java.util.*;

import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.protocol.*;

public class TableScoreCaching implements ScoreCaching {

	private final static String TABLE_NAME = "exeselfscores";
	private final static String SIMILARITY_KEY = "similarity";
	private final static String SIGNIFICANCE_KEY = "significance";
	private final static int VALUES_PER_QUERY = 100;
	private FunctionDatabase db;				// Active connection to the database
	private TreeMap<String, Float> cacheMap;	// In memory cache of scores, indexed by md5 string
	private double simThreshold;				// similarity threshold loaded from file
	private double sigThreshold;				// significance threshold loaded from file
	private QueryOptionalValues queryValue;		// Template for querying scores
	private InsertOptionalValues insertValue;	// Template for inserting scores

	public TableScoreCaching(FunctionDatabase d) {
		db = d;
		cacheMap = null;
		simThreshold = -1.0;
		sigThreshold = -1.0;
		queryValue = new QueryOptionalValues();
		queryValue.tableName = TABLE_NAME;
		queryValue.keyType = Types.VARCHAR;
		queryValue.valueType = Types.REAL;
		queryValue.keys = new Object[1];
		insertValue = new InsertOptionalValues();
		insertValue.tableName = TABLE_NAME;
		insertValue.keyType = Types.VARCHAR;
		insertValue.valueType = Types.REAL;
		insertValue.keys = new Object[1];
		insertValue.values = new Object[1];
	}

	/**
	 * Do minimal work to set up query template for a given number of values
	 * @param size is the number of values to be queried
	 */
	private void setUpQuery(int size) {
		if (queryValue != null && queryValue.keys.length == size) {
			return;
		}
		queryValue.keys = new Object[size];
	}

	/**
	 * Do minimal work to set up insert template for a given number of values
	 * @param size is the number of values to be inserted
	 */
	private void setUpInsert(int size) {
		if (insertValue != null && insertValue.keys.length == size) {
			return;
		}
		insertValue.keys = new Object[size];
		insertValue.values = new Object[size];
	}

	/**
	 * Make sure the backing database table exists, and if it doesn't, create it.
	 * If the table existed previously, try to read thresholds from it
	 * @throws LSHException for problems with the connection
	 */
	private void initialize() throws LSHException {
		if (cacheMap != null) {
			return;
		}
		cacheMap = new TreeMap<String, Float>();
		QueryOptionalExist query = new QueryOptionalExist();
		query.tableName = TABLE_NAME;
		query.keyType = Types.VARCHAR;
		query.valueType = Types.REAL;
		query.attemptCreation = true;		// Create table if it doesn't already exist
		ResponseOptionalExist response = query.execute(db);
		if (response == null) {
			throw new LSHException(db.getLastError().message);
		}
		if (response.wasCreated) {
			return;
		}
		setUpQuery(2);
		queryValue.keys[0] = SIMILARITY_KEY;
		queryValue.keys[1] = SIGNIFICANCE_KEY;
		ResponseOptionalValues optionalresponse = queryValue.execute(db);
		if (optionalresponse == null) {
			throw new LSHException(db.getLastError().message);
		}
		Float simObj = (Float) optionalresponse.resultArray[0];
		Float sigObj = (Float) optionalresponse.resultArray[1];
		if (simObj != null && sigObj != null) {
			simThreshold = simObj.doubleValue();
			sigThreshold = sigObj.doubleValue();
		}
	}

	@Override
	public void prefetchScores(Set<ExecutableRecord> exeSet, List<ExecutableRecord> missing)
			throws LSHException {
		initialize();
		int size = exeSet.size();
		Iterator<ExecutableRecord> iter = exeSet.iterator();
		ExecutableRecord[] queryGroup = new ExecutableRecord[VALUES_PER_QUERY];
		while (size > 0) {
			int curSize = size > VALUES_PER_QUERY ? VALUES_PER_QUERY : size;
			setUpQuery(curSize);
			for (int i = 0; i < curSize; ++i) {
				queryGroup[i] = iter.next();
				queryValue.keys[i] = queryGroup[i].getMd5();
			}
			ResponseOptionalValues response = queryValue.execute(db);
			if (response == null) {
				throw new LSHException(db.getLastError().message);
			}
			Object[] result = response.resultArray;
			for (int i = 0; i < curSize; ++i) {
				if (result[i] != null) {
					cacheMap.put((String) queryValue.keys[i], (Float) result[i]);
				}
				else if (missing != null) {
					missing.add(queryGroup[i]);
				}
			}
			size -= curSize;
		}
	}

	@Override
	public float getSelfScore(String md5) throws LSHException {
		initialize();
		Float val = cacheMap.get(md5);
		if (val != null) {
			return val.floatValue();
		}
		setUpQuery(1);
		queryValue.keys[0] = md5;
		ResponseOptionalValues response = queryValue.execute(db);
		if (response == null) {
			throw new LSHException(db.getLastError().message);
		}
		val = (Float) response.resultArray[0];
		if (val == null) {
			throw new LSHException("Self-score not recorded for " + md5);
		}
		cacheMap.put(md5, val);
		return val.floatValue();
	}

	@Override
	public void commitSelfScore(String md5, float score) throws LSHException {
		initialize();
		Float val = score;
		cacheMap.put(md5, val);
		setUpInsert(1);
		insertValue.keys[0] = md5;
		insertValue.values[0] = val;
		ResponseOptionalExist response = insertValue.execute(db);
		if (response == null) {
			throw new LSHException(db.getLastError().message);
		}
	}

	@Override
	public double getSimThreshold() throws LSHException {
		initialize();
		return simThreshold;
	}

	@Override
	public double getSigThreshold() throws LSHException {
		initialize();
		return sigThreshold;
	}

	@Override
	public void resetStorage(double simThresh, double sigThresh) throws LSHException {
		simThreshold = simThresh;
		sigThreshold = sigThresh;
		cacheMap = new TreeMap<String, Float>();				// Clear the cache
		QueryOptionalExist query = new QueryOptionalExist();
		query.tableName = TABLE_NAME;
		query.keyType = Types.VARCHAR;
		query.valueType = Types.REAL;
		query.attemptCreation = false;
		query.clearTable = true;								// Clear out the table
		ResponseOptionalExist response = query.execute(db);
		if (response == null) {
			throw new LSHException(db.getLastError().message);
		}
		if (!response.tableExists) {
			throw new LSHException("Optional table does not exist when it should: " + TABLE_NAME);
		}
		setUpInsert(2);
		insertValue.keys[0] = SIMILARITY_KEY;
		insertValue.keys[1] = SIGNIFICANCE_KEY;
		insertValue.values[0] = Float.valueOf((float) simThreshold);		// Write thresholds to special table rows
		insertValue.values[1] = Float.valueOf((float) sigThreshold);
		if (insertValue.execute(db) == null) {
			throw new LSHException("Unable to initialize new thresholds: " + TABLE_NAME);
		}
	}

}
