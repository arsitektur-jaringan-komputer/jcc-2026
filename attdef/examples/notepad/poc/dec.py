def loud(fn):
    def wrapper(*args):
        print("about to call", fn.__name__)
        fn(*args)
    return wrapper

@loud
def greet(name):
    print(f"hello {name}")

greet("bob")