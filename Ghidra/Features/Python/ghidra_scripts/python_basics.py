# Examples of basic Python
# @category: Examples.Python

# Python data types
my_int = 32
print my_int
print hex(my_int)

my_bool = True
print my_bool
print not my_bool

my_string = 'this is a string'
print my_string
print my_string[:4]
print my_string[-5:]
print type(my_string)

my_list = ["a", 2, 5.3, my_string]
print my_list
print my_list[1]
print my_list[1:2]
print my_list + [1, 2, 3]
print type(my_list)

my_tuple = (1, 2, 3)
print my_tuple
print my_tuple + (4,)
print type(my_tuple)

my_dictionary = {"key1": "1", "key2": 2, "key3": my_list}
print my_dictionary["key3"]
print type(my_dictionary)

my_null = None
print my_null
print type(my_null)

# Python conditionals
if len(my_string) == 16:
    print "length of my_string is 16!"

if 4 not in my_list:
    print "4 is not in my_list!"

if type(my_dictionary) == type(dict):
    print "my_dictionary is a dictionary!"

if my_null is None and 2 + 2 == 4:
    print "my_null is None and 2 + 2 == 4!"

# Python loops
for i in range(1, 10):
    print i

for letter in "word":
    print letter

for element in [100, 200, 300]:
    print element

for key in my_dictionary:
    print "%s:%s" % (key, my_dictionary[key])

i = 5
while i < 8:
    print i
    i += 1 

# Python functions
def factorial(n):
    if n == 0:
        return 1
    return n * factorial(n-1)

i = 4
print str(i) + "! = " + str(factorial(4))

# Python exceptions
def error_function():
    raise IOError("An IO error occurred!")

try:
    error_function()
    print "I won't print"
except IOError as e:
    print e.message

# Python class
class Employee:
    def __init__(self, id, name):
        self.id = id
        self.name = name

    def getId(self):
        return self.id

    def getName(self):
        return self.name

e = Employee(5555, "Snoopy")
print e.getName()
