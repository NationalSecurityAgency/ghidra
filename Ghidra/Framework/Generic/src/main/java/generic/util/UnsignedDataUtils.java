/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package generic.util;

import ghidra.util.Conv;

/**
 * A class for performing unsigned comparisons
 * of java primitives.
 * 
 * 
 */
public class UnsignedDataUtils {

	private UnsignedDataUtils() {
	}

	/**
	 * Simple test for the Comp class.
	 * @param args not used
	 */
    public static void main(String [] args) {
        System.out.println((byte)5<(byte)250);
        System.out.println(unsignedLessThan((byte)5,(byte)250));
        System.out.println(0x5<0x87654321);
        System.out.println(unsignedLessThan(0x5,0x87654321));
    }

    private final static int LESS_THAN             = 0;
    private final static int LESS_THAN_OR_EQUAL    = 1;
    private final static int GREATER_THAN          = 2;
    private final static int GREATER_THAN_OR_EQUAL = 3;

    private static boolean comp(int type, byte i, byte j) {
        return comp(type,
                    Conv.byteToLong(i),
                    Conv.byteToLong(j));
    }
    private static boolean comp(int type, short i, short j) {
        return comp(type,
                    Conv.shortToLong(i),
                    Conv.shortToLong(j));
    }
    private static boolean comp(int type, int i, int j) {
        return comp(type,
                    Conv.intToLong(i),
                    Conv.intToLong(j));
    }
    private static boolean comp(int type, long i, long j) {
        boolean isHiBitSetI = i < 0;
        boolean isHiBitSetJ = j < 0;

        if (isHiBitSetI == isHiBitSetJ) {//same sign...
            switch (type) {
	            case LESS_THAN:
	                return (i < j);
	            case LESS_THAN_OR_EQUAL:
	                return (i <= j);
	            case GREATER_THAN:
	                return (i > j);
	            case GREATER_THAN_OR_EQUAL:
	                return (i >= j);
            } 
        }
        else if (isHiBitSetI) {
            switch (type) {
	            case LESS_THAN:
	            case LESS_THAN_OR_EQUAL:
	                return false;
	            case GREATER_THAN:
	            case GREATER_THAN_OR_EQUAL:
	                return true;
	        } 
        }
        else {
            switch (type) {
	            case LESS_THAN:
	            case LESS_THAN_OR_EQUAL:
	                return true;
	            case GREATER_THAN:
	            case GREATER_THAN_OR_EQUAL:
	                return false;
	        } 
        }
        throw new RuntimeException("BAD COMP TYPE!");
    }

    /**
     * Returns true if <code>i</code> is LESS THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than <code>j</code>
     */
    public static boolean unsignedLessThan(byte i, byte j) {
        return comp(LESS_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is LESS THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than or equal to <code>j</code>
     */
    public static boolean unsignedLessThanOrEqual(byte i, byte j) {
        return comp(LESS_THAN_OR_EQUAL, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than <code>j</code>
     */
    public static boolean unsignedGreaterThan(byte i, byte j) {
        return comp(GREATER_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than or equal to <code>j</code>
     */
    public static boolean unsignedGreaterThanOrEqual(byte i, byte j) {
        return comp(GREATER_THAN_OR_EQUAL, i, j);
    }

    /**
     * Returns true if <code>i</code> is LESS THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than <code>j</code>
     */
    public static boolean unsignedLessThan(short i, short j) {
        return comp(LESS_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is LESS THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than or equal to <code>j</code>
     */
    public static boolean unsignedLessThanOrEqual(short i, short j) {
        return comp(LESS_THAN_OR_EQUAL, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than <code>j</code>
     */
    public static boolean unsignedGreaterThan(short i, short j) {
        return comp(GREATER_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than or equal to <code>j</code>
     */
    public static boolean unsignedGreaterThanOrEqual(short i, short j) {
        return comp(GREATER_THAN_OR_EQUAL, i, j);
    }

    /**
     * Returns true if <code>i</code> is LESS THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than <code>j</code>
     */
    public static boolean unsignedLessThan(int i, int j) {
        return comp(LESS_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is LESS THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than or equal to <code>j</code>
     */
    public static boolean unsignedLessThanOrEqual(int i, int j) {
        return comp(LESS_THAN_OR_EQUAL, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than <code>j</code>
     */
    public static boolean unsignedGreaterThan(int i, int j) {
        return comp(GREATER_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is greater than or equal to <code>j</code>
     */
    public static boolean unsignedGreaterThanOrEqual(int i, int j) {
        return comp(GREATER_THAN_OR_EQUAL, i, j);
    }

    /**
     * Returns true if <code>i</code> is LESS THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than <code>j</code>
     */
    public static boolean unsignedLessThan(long i, long j) {
        return comp(LESS_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is LESS THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return true if <code>i</code> is less than or equal to <code>j</code>
     */
    public static boolean unsignedLessThanOrEqual(long i, long j) {
        return comp(LESS_THAN_OR_EQUAL, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return return true if <code>i</code> is greater than <code>j</code>
     */
    public static boolean unsignedGreaterThan(long i, long j) {
        return comp(GREATER_THAN, i, j);
    }
    /**
     * Returns true if <code>i</code> is GREATER THAN or EQUAL TO <code>j</code>.
     * 
     * @param i an argument
     * @param j another argument
     * 
     * @return return true if <code>i</code> is greater than or equal to <code>j</code>
     */
    public static boolean unsignedGreaterThanOrEqual(long i, long j) {
        return comp(GREATER_THAN_OR_EQUAL, i, j);
    }
}
