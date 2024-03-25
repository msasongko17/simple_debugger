#include <iostream>

void foo() {
	int a = 1, b = 2, c = 3;
	int sum = 0;
	sum = a + b + c;
	std::cerr << sum << "\n";
}

int main() {
	std::cerr << "before foo\n";
	foo();
	std::cerr << "after foo\n";
	return 0;
}
