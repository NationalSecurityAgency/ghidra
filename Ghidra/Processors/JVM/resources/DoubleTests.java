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
class DoubleTests{

    public float double2float(double x){
        return (float) x;
    }
 
    public int double2int(double x){
        return (int) x;
    }

    public long double2long(double x){
        return (long) x;
    }

   public double doubleAdd(double x, double y){
       return x+y;
   }

   public int doubleComparison1(double x, double y){
       if (x < y){
           return 1;
       }
       return 0;
   }

   public int doubleComparison2(double x, double y){
       if (x==y) {
           return 1;
       }
       return 0;
   }

   public int doubleComparison3(double x, double y){
      if (x > y){
          return 1;
      }
      return 0;
   }

   public double return0(){
       return 0.0;
   }

   public double return1(){
       return 1.0;
   }

   public double divTest(double x, double y){
       return x/y;
   }
   
   public double mulTest(double x, double y){
       return x * y;
   }

   public double negTest(double x){
       return -x;
   }

   public double remText(double x, double y){
      return x % y;
   }

   public double subTest(double x, double y){
       return x - y;
   }
}
