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
class GetPutFieldTest{
   
    public boolean testBoolean = true;
    public byte testByte = 1;
    public short testShort = 2;
    public char testChar = 3;
    public int testInt = 4;
    public float testFloat = 1.1f;
    public double testDouble = 2.2;
    public long testLong = 0x1234567812345678l;
    public Integer testRef = new Integer(0);
    public int[] test1dArray;
    public int[][] test2dArray;
    public Class testClass = String.class;

    public Class getTestClass(){
        return testClass;
    }

    public void setTestClass(Class clazz){
        this.testClass = clazz;
    }


    public boolean getBoolean(){
        return testBoolean;
    }

    public void setBoolean(boolean newVal){
    this.testBoolean = newVal;
    }

    public byte getByte(){
        return testByte;
    }

    public void setByte(byte newVal){
       this.testByte = newVal;
    }

    public short getShort(){
        return testShort;
    }

    public void setShort(short newVal){
         this.testShort = newVal;
    }

    public char getChar(){
        return testChar;
    }

    public void setChar(char newVal){
        this.testChar = newVal;
    }

    public float getFloat(){
        return testFloat;
    }

    public void setFloat(float newVal){
        this.testFloat = newVal;
    }
    
    public int getInt(){
        return testInt;
    }

    public void setInt(int newVal){
        this.testInt = newVal;
    }

    public double getDouble(){
        return testDouble;
    }

    public void setDouble(double newVal){
        this.testDouble = newVal;
    }

    public long getLong(){
        return testLong;
    }
    
    public void setLong(long newVal){
       this.testLong = newVal;
    }

    public Integer getRef(){
        return testRef;
    }

    public void setRef(Integer newVal){
        this.testRef = newVal;
    }

    public int[] get1dArray(){
        return test1dArray;
    }

    public void set1dArray(int[] newVal){
        this.test1dArray = newVal;
    }

    public int[][] get2dArray(){
        return test2dArray;
    }

    public void set2dArray(int[][] newVal){
        this.test2dArray = newVal;
    }

    public int test3Calls(){
       return this.testInt + this.testShort + this.testByte;
    }

    public void setFloatConst(){
        float test = 2.0f;
        this.testFloat=test;
    }

    public double getDoubleFromRef(GetPutFieldTest x){
        return x.testDouble;
    }
  
    public long getLongFromRef(GetPutFieldTest x){
        return x.testLong;
    }

    public long getLongFromRef2(GetPutFieldTest x){
        long a = x.testLong;
        return a;
    }
 
    public int getIntFromRef(GetPutFieldTest x){
        return x.testInt;
    }

    public void setLongForRef(GetPutFieldTest x, long y){
        x.testLong = y;
    }

    public void setIntForRef(GetPutFieldTest x, int y){
        x.testInt = y;
    }
}
