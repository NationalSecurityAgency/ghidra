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
import java.util.ArrayList;

class ArrayTests{


   public Integer[] referenceArrayTest(Integer[] input){
       Integer[] array = new Integer[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }  
  
   public int[][] primitiveMultiArrayTest(int[][] input){
       int[][] array = new int[5][5];
       array[0][1] = input[0][1];
       array[1][0] = input[1][0];
       array[2][4] = input[2][4];
       array[4][2] = input[4][2];
       return array;
   }

   public Integer[][][] referenceMultiArrayTest(Integer[][][] input){
      Integer[][][] array = new Integer[2][2][2];
      array[0][1][2] = input[0][1][2];
      array[2][1][0] = input[2][1][0];
      return array;
   }   
  
   public Integer twoMultiAnewArrayCalls(){
       Integer[][][][][] one = new Integer[1][2][3][4][5];
       Integer[][][][][][] two = new Integer[1][2][3][4][5][6];
       return one[1][2][3][4][5] + two[1][2][3][4][5][6];
    }
 

   public boolean[] booleanArrayTest(boolean[] input){
       boolean[] array = new boolean[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }
   public byte[] byteArrayTest(byte[] input){
       byte[] array = new byte[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public char[] charArrayTest(char[] input){
       char[] array = new char[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public short[] shortArrayTest(short[] input){
       short[] array = new short[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public int[] intArrayTest(int[] input){
       int[] array = new int[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public float[] floatArrayTest(float[] input){
       float[] array = new float[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public long[] longArrayTest(long[] input){
       long[] array = new long[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }

   public double[] doubleArrayTest(double[] input){
       double[] array = new double[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }
   
   public Comparable[] comparableArrayTest(Comparable[] input){
       Comparable[] array = new Comparable[2];
       array[0] = input[0];
       array[1] = input[1];
       return array;
   }


   public void voidComparableArrayTest(Comparable[] input){
       Comparable[] array = new Comparable[2];
       array[0] = input[0];
       array[1] = input[1];
   }


   public ArrayList<Comparable> comparableArrayListTest(Comparable[] input){
       ArrayList<Comparable> array = new ArrayList<>();
       array.add(input[0]);
       array.add(input[1]);
       return array;
   }

   public int[] zeroPrimitive(){
       return new int[0];
   }

   public Integer[] zeroReference(){
      return new Integer[0];
   }

   public Comparable[] zeroInterface(){
       return new Comparable[0];
   }

   public Comparable[] dwarfTest(){
       ArrayList<Comparable> arrayList = new ArrayList<>();
       return comparableArrayTest(arrayList.toArray(new Comparable[0]));
  }
   
   public Comparable[] dwarfTest2(){
       ArrayList<Comparable> arrayList = new ArrayList<>();
       Comparable[] ret = comparableArrayTest(arrayList.toArray(new Comparable[0]));
       Integer test = new Integer(3);
       return ret;
  }

  public void referenceArrayNoUse(){
      Integer[] array = new Integer[0];
  }

  public void passArrayToVoidFunc(){
      voidComparableArrayTest(new Integer[0]);
  }


  public void primitiveNoUse(){
     int[] array = new int[0];
  }

  public void noArray(){
      Integer a = new Integer(0);
  }


}
