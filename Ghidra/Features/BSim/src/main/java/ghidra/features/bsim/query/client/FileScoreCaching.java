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

import java.io.*;
import java.util.*;

import ghidra.features.bsim.query.LSHException;
import ghidra.features.bsim.query.description.ExecutableRecord;

public class FileScoreCaching implements ScoreCaching {

	private File storageFile;					// File holding the score data
	private TreeMap<String, Float> cacheMap;		// In memory cache of scores, indexed by md5 string
	private double simThreshold;				// similarity threshold loaded from file
	private double sigThreshold;				// significance threshold loaded from file

	public FileScoreCaching(String fileName) {
		storageFile = new File(fileName);
		cacheMap = null;
		simThreshold = -1.0;		// Negative indicates thresholds have not been configured
		sigThreshold = -1.0;
	}

	private void loadCache() throws IOException {
		if (cacheMap != null) {
			return;
		}
		if (!storageFile.exists()) {
			return;							// File doesn't exist, it will get created on first commitSelfScore call
		}
		cacheMap = new TreeMap<String, Float>();
		BufferedReader reader = new BufferedReader(new FileReader(storageFile));
		String floatString = reader.readLine();
		if (floatString == null) {
			reader.close();
			throw new IOException("Score file missing threshold lines");
		}
		simThreshold = Float.parseFloat(floatString);
		floatString = reader.readLine();
		if (floatString == null) {
			reader.close();
			throw new IOException("Score file missing threshold lines");
		}
		sigThreshold = Float.parseFloat(floatString);
		floatString = reader.readLine();
		while (floatString != null) {
			String[] split = floatString.split(" ");
			if (split.length != 2 || split[0].length() != 32) {
				reader.close();
				throw new IOException("Bad line in score file");
			}
			float val = Float.parseFloat(split[1]);
			cacheMap.put(split[0], val);
			floatString = reader.readLine();
		}
		reader.close();
	}

	@Override
	public float getSelfScore(String md5) throws LSHException {
		try {
			loadCache();
		}
		catch (IOException e) {
			throw new LSHException("Could not recover cached scores: " + e.getMessage());
		}
		if (cacheMap != null) {
			Float val = cacheMap.get(md5);
			if (val != null) {
				return val.floatValue();
			}
		}
		throw new LSHException("Self-score not recorded for " + md5);
	}

	@Override
	public void commitSelfScore(String md5, float score) throws LSHException {
		try {
			BufferedWriter writer = new BufferedWriter(new FileWriter(storageFile, true));
			if (cacheMap == null) {
				writer.write(Double.toString(simThreshold));
				writer.newLine();
				writer.write(Double.toString(sigThreshold));
				writer.newLine();
				cacheMap = new TreeMap<String, Float>();
			}
			cacheMap.put(md5, score);
			writer.write(md5);
			writer.append(' ');
			writer.write(Float.toString(score));
			writer.newLine();
			writer.close();
		}
		catch (IOException ex) {
			throw new LSHException("Could not commit self-score: " + ex.getMessage());
		}
	}

	@Override
	public double getSimThreshold() throws LSHException {
		try {
			loadCache();
		}
		catch (IOException e) {
			throw new LSHException("Problems loading score cache: " + e.getMessage());
		}
		return simThreshold;
	}

	@Override
	public double getSigThreshold() throws LSHException {
		try {
			loadCache();
		}
		catch (IOException e) {
			throw new LSHException("Problems loading score cache: " + e.getMessage());
		}
		return sigThreshold;
	}

	@Override
	public void prefetchScores(Set<ExecutableRecord> exeSet, List<ExecutableRecord> missing)
			throws LSHException {
		try {
			loadCache();
		}
		catch (IOException e) {
			throw new LSHException("Could not prefetch scores: " + e.getMessage());
		}
		if (missing != null) {
			if (cacheMap == null) {
				for (ExecutableRecord exeRec : exeSet) {
					missing.add(exeRec);			// Everything is missing
				}
			}
			else {
				for (ExecutableRecord exeRec : exeSet) {
					if (!cacheMap.containsKey(exeRec.getMd5())) {
						missing.add(exeRec);
					}
				}
			}
		}
	}

	@Override
	public void resetStorage(double simThresh, double sigThresh) throws LSHException {
		if (storageFile.exists()) {
			storageFile.delete();
		}
		cacheMap = null;
		simThreshold = simThresh;
		sigThreshold = sigThresh;
	}
}
