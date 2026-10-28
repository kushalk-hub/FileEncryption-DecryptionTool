#ifndef CIRCULAR_ARR_QUEUE_CPP
#define CIRCULAR_ARR_QUEUE_CPP

template <typename T>
class CircularQueue {
private:
    T* arr;
    int capacity;
    int head;
    int tail;
    int count;

public:
    CircularQueue(int cap = 10) : capacity(cap), head(0), tail(0), count(0) {
        arr = new T[capacity];
    }

    ~CircularQueue() {
        delete[] arr;
    }

    bool enqueue(const T& item) {
        if (count == capacity) return false;
        arr[tail] = item;
        tail = (tail + 1) % capacity;
        count++;
        return true;
    }

    bool dequeue() {
        if (count == 0) return false;
        head = (head + 1) % capacity;
        count--;
        return true;
    }

    int size() const {
        return count;
    }
};

#endif
