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
package ghidra.file.formats.android.versions;

/**
 * https://developer.android.com/studio/releases/platforms
 * <br>
 * https://en.wikipedia.org/wiki/Android_version_history#Overview
 */
public enum AndroidVersion {
	//@formatter:off
	VERSION_1_5  ( 3, "1.5",   'C', "Cupcake"),
	VERSION_1_6  ( 4, "1.5",   'D', "Donut"),
	VERSION_2_0  ( 5, "2.0",   'E', "Eclair"),
	VERSION_2_0_1( 6, "2.0.1", 'E', "Eclair"),
	VERSION_2_1  ( 7, "2.1",   'E', "Eclair"),
	VERSION_2_2  ( 8, "2.2",   'F', "Froyo"),
	VERSION_2_2_1( 8, "2.2.1", 'F', "Froyo"),
	VERSION_2_2_2( 8, "2.2.2", 'F', "Froyo"),
	VERSION_2_2_3( 8, "2.2.3", 'F', "Froyo"),
	VERSION_2_3  ( 9, "2.3",   'G', "Gingerbread"),
	VERSION_2_3_1( 9, "2.3.1", 'G', "Gingerbread"),
	VERSION_2_3_2( 9, "2.3.2", 'G', "Gingerbread"),
	VERSION_2_3_3(10, "2.3.3", 'G', "Gingerbread"),
	VERSION_2_3_4(10, "2.3.4", 'G', "Gingerbread"),
	VERSION_2_3_5(10, "2.3.5", 'G', "Gingerbread"),
	VERSION_2_3_6(10, "2.3.6", 'G', "Gingerbread"),
	VERSION_2_3_7(10, "2.3.7", 'G', "Gingerbread"),
	VERSION_3_0  (11, "3.0",   'H', "Honeycomb"),
	VERSION_3_1  (12, "3.1",   'H', "Honeycomb"),
	VERSION_3_2  (13, "3.2",   'H', "Honeycomb"),
	VERSION_3_2_1(13, "3.2.1", 'H', "Honeycomb"),
	VERSION_3_2_2(13, "3.2.2", 'H', "Honeycomb"),
	VERSION_3_2_3(13, "3.2.3", 'H', "Honeycomb"),
	VERSION_3_2_4(13, "3.2.4", 'H', "Honeycomb"),
	VERSION_3_2_5(13, "3.2.5", 'H', "Honeycomb"),
	VERSION_3_2_6(13, "3.2.6", 'H', "Honeycomb"),
	VERSION_4_0  (14, "4.0",   'I', "Ice Cream Sandwich"),
	VERSION_4_0_1(14, "4.0.1", 'I', "Ice Cream Sandwich"),
	VERSION_4_0_2(14, "4.0.2", 'I', "Ice Cream Sandwich"),
	VERSION_4_0_3(15, "4.0.3", 'I', "Ice Cream Sandwich"),
	VERSION_4_0_4(15, "4.0.4", 'I', "Ice Cream Sandwich"),
	VERSION_4_1  (16, "4.1",   'J', "Jelly Bean"),
	VERSION_4_1_1(16, "4.1.1", 'J', "Jelly Bean"),
	VERSION_4_1_2(16, "4.1.2", 'J', "Jelly Bean"),
	VERSION_4_2  (17, "4.2",   'J', "Jelly Bean"),
	VERSION_4_2_1(17, "4.2.1", 'J', "Jelly Bean"),
	VERSION_4_2_2(17, "4.2.1", 'J', "Jelly Bean"),
	VERSION_4_3  (18, "4.3",   'J', "Jelly Bean"),
	VERSION_4_3_1(18, "4.3.1", 'J', "Jelly Bean"),
	VERSION_4_4  (19, "4.4",   'K', "KitKat"),
	VERSION_4_4_1(19, "4.4.1", 'K', "KitKat"),
	VERSION_4_4_2(19, "4.4.2", 'K', "KitKat"),
	VERSION_4_4_3(19, "4.4.3", 'K', "KitKat"),
	VERSION_4_4_4(19, "4.4.4", 'K', "KitKat"),
	VERSION_4_4_W(20, "4.4W",  'K', "KitKat"),
	VERSION_5_0  (21, "5.0",   'L', "Lollipop"),
	VERSION_5_0_1(21, "5.0.1", 'L', "Lollipop"),
	VERSION_5_0_2(21, "5.0.2", 'L', "Lollipop"),
	VERSION_5_1  (22, "5.1",   'L', "Lollipop"),
	VERSION_5_1_1(22, "5.1.1", 'L', "Lollipop"),
	VERSION_6_0  (23, "6.0",   'M', "Marshmallow"),
	VERSION_6_0_1(23, "6.0.1", 'M', "Marshmallow"),
	VERSION_7_0  (24, "7.0",   'N', "Nougat"),
	VERSION_7_1  (25, "7.1",   'N', "Nougat"),
	VERSION_7_1_1(25, "7.1.1", 'N', "Nougat"),
	VERSION_7_1_2(25, "7.1.2", 'N', "Nougat"),
	VERSION_8_0  (26, "8.0",   'O', "Oreo"),
	VERSION_8_1  (27, "8.1",   'O', "Oreo"),
	VERSION_9    (28, "9",     'P', "Pie"),
	VERSION_10   (29, "10",    'Q', "Quince Tart"),
	VERSION_11   (30, "11",    'R', "Red Velvet Cake"),
	VERSION_12   (31, "12",    'S', "Snow Cone"),
	VERSION_12_L (32, "12L",   'S', "Snow Cone v2"),
	VERSION_13   (33, "13",    'T', "Tiramisu"),

	UNKNOWN      ( 0, "0",     '\0', "");
	//@formatter:on

	public static final int INVALID_API_VALUE = -1;

	private int apiVersion;
	private String versionNumber;
	private char versionLetter;
	private String versionName;

	private AndroidVersion(int apiVersion, String versionNumber, char versionLetter,
			String versionName) {

		this.apiVersion = apiVersion;
		this.versionNumber = versionNumber;
		this.versionLetter = versionLetter;
		this.versionName = versionName;
	}

	/**
	 * Returns the API version.
	 * For example, 24, 25, 26, etc.
	 * @return the API version
	 */
	public int getApiVersion() {
		return apiVersion;
	}

	/**
	 * Returns the OS version.
	 * For example, "4.0", "5.0.1", etc.
	 * @return the OS version
	 */
	public String getVersionNumber() {
		return versionNumber;
	}

	/**
	 * Returns the version letter.
	 * For example, "S", "T", etc.
	 * @return the version letter
	 */
	public char getVersionLetter() {
		return versionLetter;
	}

	/**
	 * Returns the version name.
	 * For example, "KitKat", "Oreo", etc.
	 * @return the version name
	 */
	public String getVersionName() {
		return versionName;
	}

}
