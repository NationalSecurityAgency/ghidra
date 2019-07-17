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
package ghidra.app.plugin.core.string;

import generic.jar.ResourceFile;
import ghidra.framework.Application;

import java.io.*;
import java.util.*;

public class NGramUtils {

	private static final int ASCII_CHAR_COUNT = 128;
	private static ModelLogProbabilities logProbs = null;
	private static String lastLoadedTrigramModel = "";
	private static String lastLoadedTrigramModelPath = "";
	private static boolean initializationsDone = false;

	private static final String MODEL_FILE_EXTENSION = "sng";
	private static final String MODEL_TYPE_PREFIX = "Model Type: ";
	private static String modelType = "";

	// "Bad" log to be used as default score when we know the string is bad
	private static double defaultLogValue = -20d;

	private static int minimumStringLength = 3;

	/**
	 *  Thresholds by string length.  Index represents string length (i.e., length 4 threshold
	 *  is -2.71). StrLen > 100, use -6.3 as threshold.
	 *  <p>
	 *  The 'ngThresholds' array stores thresholds for strings shorter than the minimum string 
	 *  length, even though they are not scored. This is a convenience so that we can use the 
	 *  array to look up threshold by string length.
	 *  <p>
	 *  Set string lengths in range 0 - 3 to a threshold of 10 -- since scores are always negative, 
	 *  there is no way they will be greater than 10!
	 */
	//@formatter:off
	private static final Double[] NG_THRESHOLDS = new Double[] { 
		10.0, 10.0, 10.0, 10.0, -2.71, -3.26, -3.52, -3.84, -4.23, -4.49,        	// 0 - 9
		-4.55, -4.74, -4.88, -5.03, -5.06, -5.2, -5.24, -5.29, -5.29, -5.42, 		// 10 - 19
		-5.51, -5.52, -5.53, -5.6, -5.6, -5.62, -5.7, -5.7, -5.78, -5.79, 			// 20 - 29
		-5.81, -5.81, -5.84, -5.85, -5.86, -5.88, -5.92, -5.92, -5.93, -5.95, 		// 30 - 39
		-5.99, -6.0, -6.0, -6.0, -6.02, -6.02, -6.02, -6.05, -6.06, -6.07,			// 40 - 49
		-6.08, -6.1, -6.12, -6.12, -6.13, -6.13, -6.13, -6.13, -6.13, -6.13,		// 50 - 59
		-6.13, -6.15, -6.15, -6.16, -6.16, -6.16, -6.17, -6.19, -6.19, -6.21,		// 60 - 69
		-6.21, -6.21, -6.21, -6.21, -6.21, -6.25, -6.25, -6.25, -6.25, -6.25,		// 70 - 79 
		-6.25, -6.25, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, -6.26, 		// 80 - 89
		-6.26, -6.29, -6.29, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3, -6.3 		// 90 - 100
		};
	//@formatter:on

	private static final double MAX_NG_THRESHOLD = -6.3;

	private static HashMap<String, Integer> descriptionToAsciiInt;

	private static void assignDescriptionsToASCIINums() {
		descriptionToAsciiInt = new HashMap<String, Integer>();
		descriptionToAsciiInt.put("[NUL]", 0);
		descriptionToAsciiInt.put("[SOH]", 1);
		descriptionToAsciiInt.put("[STX]", 2);
		descriptionToAsciiInt.put("[ETX]", 3);
		descriptionToAsciiInt.put("[EOT]", 4);
		descriptionToAsciiInt.put("[ENQ]", 5);
		descriptionToAsciiInt.put("[ACK]", 6);
		descriptionToAsciiInt.put("[BEL]", 7);
		descriptionToAsciiInt.put("[BS]", 8);
		descriptionToAsciiInt.put("[HT]", 9);
		descriptionToAsciiInt.put("[LF]", 10);
		descriptionToAsciiInt.put("[VT]", 11);
		descriptionToAsciiInt.put("[FF]", 12);
		descriptionToAsciiInt.put("[CR]", 13);
		descriptionToAsciiInt.put("[SO]", 14);
		descriptionToAsciiInt.put("[SI]", 15);
		descriptionToAsciiInt.put("[DLE]", 16);
		descriptionToAsciiInt.put("[DC1]", 17);
		descriptionToAsciiInt.put("[DC2]", 18);
		descriptionToAsciiInt.put("[DC3]", 19);
		descriptionToAsciiInt.put("[DC4]", 20);
		descriptionToAsciiInt.put("[NAK]", 21);
		descriptionToAsciiInt.put("[SYN]", 22);
		descriptionToAsciiInt.put("[ETB]", 23);
		descriptionToAsciiInt.put("[CAN]", 24);
		descriptionToAsciiInt.put("[EM]", 25);
		descriptionToAsciiInt.put("[SUB]", 26);
		descriptionToAsciiInt.put("[ESC]", 27);
		descriptionToAsciiInt.put("[FS]", 28);
		descriptionToAsciiInt.put("[GS]", 29);
		descriptionToAsciiInt.put("[RS]", 30);
		descriptionToAsciiInt.put("[US]", 31);
		descriptionToAsciiInt.put("[SP]", 32);
		descriptionToAsciiInt.put("[DEL]", 127);
	}

	/**
	 * Invoked when the given model should be loaded, or checked against an existing one to see if it is different (in 
	 * which case, it would be loaded).
	 * 
	 * @param trigramFile	Name of trigram model file
	 * @param forceReload	if true, reloads model (even if it is the same name as the previously-loaded model)
	 * @throws IOException
	 */
	public static void startNewSession(String trigramFile, boolean forceReload) throws IOException {

		if (!initializationsDone) {
			// Set min string length based on thresholds
			for (int i = 0; i < NG_THRESHOLDS.length; i++) {
				if (NG_THRESHOLDS[i] < 0) {
					minimumStringLength = i;
					break;
				}
			}

			assignDescriptionsToASCIINums();
			initializationsDone = true;
		}

		if (forceReload || (!lastLoadedTrigramModel.equals(trigramFile))) {
			logProbs = new ModelLogProbabilities(ASCII_CHAR_COUNT);
			loadStringModels(trigramFile);
		}
	}

	/**
	 * Invoked when the given model should be loaded.
	 * 
	 * @param model  Model to be loaded.
	 */
	public static void startNewSession(StringModel model) {
		logProbs = new ModelLogProbabilities(ASCII_CHAR_COUNT);
		loadStringModels(model);
	}

	/**
	 * Invoked when the given model file should be loaded.
	 * 
	 * @param model  Model file to be loaded
	 */
	public static void startNewSession(File model) throws IOException {
		logProbs = new ModelLogProbabilities(ASCII_CHAR_COUNT);
		loadStringModels(new FileInputStream(model), model.getName());
	}

	/**
	 * Initializes log probabilities based on counts from the given input file.
	 * 
	 * @param trigramFile     Name of trigram model file
	 * @throws IOException
	 */
	private static void loadStringModels(String trigramFile) throws IOException {

		List<ResourceFile> modelFiles =
			Application.findFilesByExtensionInApplication(MODEL_FILE_EXTENSION);

		InputStream countFileContents = null;
		String filename = "";

		ResourceFile foundFile = null;

		for (ResourceFile resourceFile : modelFiles) {
			filename = resourceFile.getName();

			if (filename.equals(trigramFile)) {
				countFileContents = resourceFile.isFile() ? resourceFile.getInputStream() : null;
				foundFile = resourceFile;
				break;
			}
		}

		if (countFileContents == null) {
			lastLoadedTrigramModelPath = "";
			lastLoadedTrigramModel = "";
			throw new IOException("Was not able to load the strings model file (" + trigramFile +
				")");
		}

		loadStringModels(countFileContents, filename);
		lastLoadedTrigramModelPath = foundFile.getAbsolutePath();
	}

	/**
	 * Initializes log probabilities based on counts from the given InputStream.
	 * 
	 * @param trigramFileStream  InputStream of trigram file contents
	 * @throws IOException
	 */
	private static void loadStringModels(InputStream trigramFileStream, String filename)
			throws IOException {

		// Assume it's a valid file (since there is a valid InputStream for it)
		ingestModel(trigramFileStream, filename);
		lastLoadedTrigramModel = filename;
	}

	/**
	 * Initializes log probabilities based on counts from the given model.
	 * 
	 * @param model  Model object containing trigram counts
	 */
	private static void loadStringModels(StringModel model) {

		int[][] beginTrigramCounts, endTrigramCounts;
		int[][][] trigramCounts;
		int copyLength;
		long totalTrigrams;

		// Make copies of models so as not to change the original model during smoothing
		int[][] tempDoubleArr = model.getBeginTrigramCounts();
		copyLength = tempDoubleArr.length;
		beginTrigramCounts = new int[copyLength][];

		for (int i = 0; i < copyLength; i++) {
			beginTrigramCounts[i] = Arrays.copyOf(tempDoubleArr[i], tempDoubleArr[i].length);
		}

		tempDoubleArr = model.getEndTrigramCounts();
		copyLength = tempDoubleArr.length;
		endTrigramCounts = new int[copyLength][];

		for (int i = 0; i < copyLength; i++) {
			endTrigramCounts[i] = Arrays.copyOf(tempDoubleArr[i], tempDoubleArr[i].length);
		}

		int[][][] tempTripleArr = model.getTrigramCounts();
		copyLength = tempTripleArr.length;
		trigramCounts = new int[copyLength][][];

		for (int i = 0; i < copyLength; i++) {
			tempDoubleArr = tempTripleArr[i];
			trigramCounts[i] = new int[tempDoubleArr.length][];

			for (int j = 0; j < tempDoubleArr.length; j++) {
				trigramCounts[i][j] = Arrays.copyOf(tempDoubleArr[j], tempDoubleArr[j].length);
			}
		}

		totalTrigrams = model.getTotalNumTrigrams();

		// Calculate log probabilities and smooth.
		smoothCountsAndCalculateLogProbs(beginTrigramCounts, endTrigramCounts, trigramCounts,
			totalTrigrams);

		lastLoadedTrigramModel = "";
	}

	/**
	 * Read in model files, smooth counts, and calculate log probabilities. 
	 * 
	 * @param charFileToSlurp  File containing character ngram counts
	 * @throws IOException
	 */
	private static void ingestModel(InputStream modelStream, String modelName) throws IOException {

		Scanner scanner1 = new Scanner(modelStream, "UTF-8");
		String currString = "";
		String[] charInfo;
		int currCount;

		int[][] beginTrigramCounts = new int[ASCII_CHAR_COUNT][ASCII_CHAR_COUNT]; // begin char is implied
		int[][] endTrigramCounts = new int[ASCII_CHAR_COUNT][ASCII_CHAR_COUNT]; // end char is implied
		int[][][] trigramCounts = new int[ASCII_CHAR_COUNT][ASCII_CHAR_COUNT][ASCII_CHAR_COUNT];

		long totalTrigrams = 0;

		// Ingest character counts file.
		try {
			while (scanner1.hasNextLine()) {

				currString = scanner1.nextLine();

				if (currString.startsWith("#")) {
					if (currString.contains(MODEL_TYPE_PREFIX)) {
						modelType = currString.substring(MODEL_TYPE_PREFIX.length() + 2);
					}
				}
				else if (currString.trim().length() > 0) {
					charInfo = currString.split("\\t");

					if (charInfo.length != 4) {
						throw new IOException("In model file " + modelName +
							", this line should split into 4 parts: " + currString);
					}
					currCount = Integer.parseInt(charInfo[3]);

					charInfo = convertToAsciiNums(charInfo);

					if (charInfo[0].equals("[^]")) {

						// Ignore the ^ 0 $ case, if somehow one-character strings were ingested during model creation
						if (!charInfo[2].equals("[$]")) {
							// Beginning of string
							beginTrigramCounts[Integer.parseInt(charInfo[1])][Integer.parseInt(charInfo[2])] +=
								currCount;
						}
					}
					else if (charInfo[2].equals("[$]")) {
						endTrigramCounts[Integer.parseInt(charInfo[0])][Integer.parseInt(charInfo[1])] +=
							currCount;
					}
					else {
						trigramCounts[Integer.parseInt(charInfo[0])][Integer.parseInt(charInfo[1])][Integer.parseInt(charInfo[2])] +=
							currCount;
					}

					totalTrigrams += currCount;
				}
			}
		}
		catch (NumberFormatException nfe) {
			throw new IOException("Can not parse line: " + currString + " in model file '" +
				modelName + "'");
		}
		finally {
			scanner1.close();
		}

		if (modelType.equals("")) {
			throw new IOException("Model file: " + modelName + " does not contain the model type.");
		}

		smoothCountsAndCalculateLogProbs(beginTrigramCounts, endTrigramCounts, trigramCounts,
			totalTrigrams);
	}

	private static String[] convertToAsciiNums(String[] inputChars) throws NumberFormatException,
			IOException {
		String[] retArr = new String[inputChars.length];

		// Don't convert the last array entry because it represents counts!
		for (int i = 0; i < retArr.length - 1; i++) {
			if (inputChars[i].length() > 1) {
				if (descriptionToAsciiInt.containsKey(inputChars[i])) {
					retArr[i] = descriptionToAsciiInt.get(inputChars[i]).toString();
				}
				else {
					if ((inputChars[i].equals("[^]")) || (inputChars[i].equals("[$]"))) {
						retArr[i] = inputChars[i];
					}
					else {
						throw new IOException("Can not parse character " + inputChars[i] +
							" in model file (expecting a string representation of an ASCII character).");
					}
				}
			}
			else {
				retArr[i] =
					new Integer(new Character(inputChars[i].charAt(0)).charValue()).toString();
			}
		}

		return retArr;
	}

	/**
	 * Smooth any 0-count entries and calculate log probabilities
	 * 
	 * @param beginTrigramCounts
	 * @param endTrigramCounts
	 * @param trigramCounts
	 * @param totalTrigrams
	 */
	private static void smoothCountsAndCalculateLogProbs(int[][] beginTrigramCounts,
			int[][] endTrigramCounts, int[][][] trigramCounts, long totalTrigrams) {

		// Smooth for non-existing trigrams
		for (int i = 0; i < ASCII_CHAR_COUNT; i++) {

			for (int j = 0; j < ASCII_CHAR_COUNT; j++) {

				if (beginTrigramCounts[i][j] == 0) {
					beginTrigramCounts[i][j] = 1;
					totalTrigrams++;
				}

				if (endTrigramCounts[i][j] == 0) {
					endTrigramCounts[i][j] = 1;
					totalTrigrams++;
				}

				for (int k = 0; k < ASCII_CHAR_COUNT; k++) {
					if (trigramCounts[i][j][k] == 0) {
						trigramCounts[i][j][k] = 1;
						totalTrigrams++;
					}
				}
			}
		}

		double[][] beginLogTrigrams = logProbs.getBeginLogTrigrams();
		double[][] endLogTrigrams = logProbs.getEndLogTrigrams();
		double[][][] logTrigrams = logProbs.getLogTrigrams();

		// Now calculate log probabilities
		for (int i = 0; i < ASCII_CHAR_COUNT; i++) {

			for (int j = 0; j < ASCII_CHAR_COUNT; j++) {
				beginLogTrigrams[i][j] =
					Math.log10((double) beginTrigramCounts[i][j] / (double) totalTrigrams);
				endLogTrigrams[i][j] =
					Math.log10((double) endTrigramCounts[i][j] / (double) totalTrigrams);

				for (int k = 0; k < ASCII_CHAR_COUNT; k++) {
					logTrigrams[i][j][k] =
						Math.log10((double) trigramCounts[i][j][k] / (double) totalTrigrams);
				}
			}
		}
	}

	/**
	 * Calculates and stores scores for the [string in the] given StringAndScores object.
	 *  
	 * @param strAndScores  Object that stores input string and associated scores
	 */
	public static void scoreString(StringAndScores strAndScores) {
		int[] asciiCodes = strAndScores.getAsciiCodes();

		double ngScore;

		if (asciiCodes.length < 3) {
			ngScore = defaultLogValue;
		}
		else {
			ngScore = calculateTrigrams(asciiCodes);
		}

		strAndScores.setNgramScore(ngScore);

		int strLen = strAndScores.getScoredStringLength();

		double thresholdToUse =
			strLen >= NG_THRESHOLDS.length ? MAX_NG_THRESHOLD : NG_THRESHOLDS[strLen];

		strAndScores.setScoreThreshold(thresholdToUse);
	}

	/**
	 * Calculates and stores scores for a list of StringAndScores objects.
	 * 
	 * @param strAndScoresList  List of StringAndScores objects
	 */
	public static void scoreStrings(List<StringAndScores> strAndScoresList) {
		for (StringAndScores sas : strAndScoresList) {
			scoreString(sas);
		}
	}

	public static int getMinimumStringLength() {
		return minimumStringLength;
	}

	/**
	 * Calculate the score for the given ASCII string (characters represented by ASCII codes)
	 * 
	 * @param asciiCodes  ASCII codes that represent the characters for candidate string
	 * @return  score for the given string
	 */
	private static double calculateTrigrams(int[] asciiCodes) {

		int stringLength = asciiCodes.length;
		int maxIndNgram = stringLength - 3;

		double localLikelihood = 0;

		double[][] beginTrigramProbs = logProbs.getBeginLogTrigrams();
		double[][] endTrigramProbs = logProbs.getEndLogTrigrams();
		double[][][] trigramProbs = logProbs.getLogTrigrams();

		// We can't calculate a score for strings less than length 3
		// Note: length of string is checked by calling method, but leave this here just in case
		if (stringLength < 3) {
			return defaultLogValue;
		}

		int charIndex = 1;
		localLikelihood += beginTrigramProbs[asciiCodes[0]][asciiCodes[1]];

		while (charIndex <= maxIndNgram) {
			localLikelihood +=
				trigramProbs[asciiCodes[charIndex]][asciiCodes[charIndex + 1]][asciiCodes[charIndex + 2]];
			charIndex++;
		}

		// Get end-of-string trigram score
		localLikelihood += endTrigramProbs[asciiCodes[charIndex]][asciiCodes[charIndex + 1]];

		return localLikelihood / stringLength;
	}

	/**
	 * Return the model type that was stored with the model.
	 * @return String
	 */
	public static String getModelType() {
		return modelType;
	}

	/**
	 * Returns true if the model is lowercase
	 * 
	 * @return boolean
	 */
	public static boolean isLowerCaseModel() {
		if (modelType.equalsIgnoreCase("lowercase")) {
			return true;
		}

		return false;
	}

	public static String getLastLoadedTrigramModel() {
		return lastLoadedTrigramModel;
	}

	public static String getLastLoadedTrigramModelPath() {
		return lastLoadedTrigramModelPath;
	}

}

/**
 * Storage for log probabilities calculated for a model (after counts have been smoothed).
 */
class ModelLogProbabilities {

	private double[][] beginLogTrigrams, endLogTrigrams;
	private double[][][] logTrigrams;

	public ModelLogProbabilities(int numAsciiChars) {
		beginLogTrigrams = new double[numAsciiChars][numAsciiChars];
		endLogTrigrams = new double[numAsciiChars][numAsciiChars];
		logTrigrams = new double[numAsciiChars][numAsciiChars][numAsciiChars];
	}

	public double[][] getBeginLogTrigrams() {
		return beginLogTrigrams;
	}

	public double[][] getEndLogTrigrams() {
		return endLogTrigrams;
	}

	public double[][][] getLogTrigrams() {
		return logTrigrams;
	}
}
