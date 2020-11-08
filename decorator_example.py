import time

def time_measure(func):
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        end = time.time()
        print
        #additional code

def calculations(num1, num2):
    return num1 + num2

def calculations2(num1, num2):
    return num1 - num2


if __name__ == '__main__':
    a = 1
    b = 100

    start = time.time()
    result = calculations(a, b)
    end = time.time()
    result2 = calculations2(a, b)
    print(f"Result of calculations: {result}")
    print("calculation needed ", end-start, "seconds")
    print(f"Result of calculations2: {result2}")