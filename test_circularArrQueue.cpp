#include <iostream>
#include <cassert>
#include "circularArrQueue.cpp"

int destructor_count = 0;

class TrackedType {
public:
    TrackedType() {}
    ~TrackedType() {
        destructor_count++;
    }
};

void test_destructor() {
    destructor_count = 0;
    {
        CircularQueue<TrackedType> queue(5);
        // The queue will allocate an array of 5 TrackedType objects.
        // Upon destruction, it should call the destructor for all 5 objects.
    }
    assert(destructor_count == 5);
    std::cout << "test_destructor passed" << std::endl;
}

void test_enqueue_dequeue() {
    CircularQueue<int> queue(3);
    assert(queue.size() == 0);
    assert(queue.enqueue(1) == true);
    assert(queue.enqueue(2) == true);
    assert(queue.enqueue(3) == true);
    assert(queue.enqueue(4) == false); // Queue is full
    assert(queue.size() == 3);

    assert(queue.dequeue() == true);
    assert(queue.size() == 2);
    assert(queue.enqueue(4) == true);
    assert(queue.size() == 3);

    assert(queue.dequeue() == true);
    assert(queue.dequeue() == true);
    assert(queue.dequeue() == true);
    assert(queue.dequeue() == false); // Queue is empty

    std::cout << "test_enqueue_dequeue passed" << std::endl;
}

int main() {
    test_destructor();
    test_enqueue_dequeue();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
