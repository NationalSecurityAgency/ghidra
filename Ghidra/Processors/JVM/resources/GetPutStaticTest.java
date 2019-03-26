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
class GetPutStaticTest{
   
    public static boolean testBoolean = true;
    public static byte testByte = 1;
    public static short testShort = 2;
    public static char testChar = 3;
    public static int testInt = 4;
    public static float testFloat = 1.1f;
    public static double testDouble = 2.2;
    public static long testLong = 5l;
    public static Integer testRef = new Integer(0);
    public static int[] test1dArray;
    public static int[][] test2dArray;

    public static boolean getBoolean(){
        return testBoolean;
    }

    public static void setBoolean(boolean newVal){
        GetPutStaticTest.testBoolean = newVal;
    }

    public static byte getByte(){
        return testByte;
    }

    public static void setByte(byte newVal){
        GetPutStaticTest.testByte = newVal;
    }

    public static short getShort(){
        return testShort;
    }

    public static void setShort(short newVal){
        GetPutStaticTest.testShort = newVal;
    }

    public static char getChar(){
        return testChar;
    }

    public static void setChar(char newVal){
        GetPutStaticTest.testChar = newVal;
    }

    public static float getFloat(){
        return testFloat;
    }

    public static void setFloat(float newVal){
        GetPutStaticTest.testFloat = newVal;
    }
    
    public static int getInt(){
        return testInt;
    }

    public static void setInt(int newVal){
        GetPutStaticTest.testInt = newVal;
    }

    public static double getDouble(){
        return testDouble;
    }

    public static void setDouble(double newVal){
        GetPutStaticTest.testDouble = newVal;
    }

    public static long getLong(){
        return testLong;
    }
    
    public static void setLong(long newVal){
        GetPutStaticTest.testLong = newVal;
    }

    public static Integer getRef(){
        return testRef;
    }

    public static void setRef(Integer newVal){
        GetPutStaticTest.testRef = newVal;
    }

    public static int[] get1dArray(){
        return test1dArray;
    }

    public static void set1dArray(int[] newVal){
        GetPutStaticTest.test1dArray = newVal;
    }

    public static int[][] get2dArray(){
        return test2dArray;
    }

    public static void set2dArray(int[][] newVal){
        GetPutStaticTest.test2dArray = newVal;
    }

    public static int test3Calls(){
        return GetPutStaticTest.testInt + GetPutStaticTest.testShort + GetPutStaticTest.testByte;
    }


    public static int test2Calls(){
        return GetPutStaticTest.testInt + GetPutStaticTest.testShort;
    }


    public static void setFloatConst(){
        float test = 2.0f;
        GetPutStaticTest.testFloat=test;
    }


}
