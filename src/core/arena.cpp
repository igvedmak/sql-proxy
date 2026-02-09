#include "core/arena.hpp"
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace sqlproxy {

Arena::Arena(size_t initial_size, size_t max_size)
    : buffer_(nullptr),
      current_(nullptr),
      capacity_(initial_size),
      max_capacity_(max_size),
      initial_size_(initial_size) {

    if (initial_size > max_size) {
        throw std::invalid_argument("Initial size cannot exceed max size");
    }

    // Allocate aligned memory
    buffer_ = static_cast<char*>(std::aligned_alloc(alignof(std::max_align_t), initial_size));
    if (!buffer_) {
        throw std::bad_alloc();
    }

    current_ = buffer_;
}

Arena::~Arena() {
    if (buffer_) {
        std::free(buffer_);
    }
}

Arena::Arena(Arena&& other) noexcept
    : buffer_(other.buffer_),
      current_(other.current_),
      capacity_(other.capacity_),
      max_capacity_(other.max_capacity_),
      initial_size_(other.initial_size_) {

    other.buffer_ = nullptr;
    other.current_ = nullptr;
    other.capacity_ = 0;
}

Arena& Arena::operator=(Arena&& other) noexcept {
    if (this != &other) {
        if (buffer_) {
            std::free(buffer_);
        }

        buffer_ = other.buffer_;
        current_ = other.current_;
        capacity_ = other.capacity_;
        max_capacity_ = other.max_capacity_;
        initial_size_ = other.initial_size_;

        other.buffer_ = nullptr;
        other.current_ = nullptr;
        other.capacity_ = 0;
    }
    return *this;
}

void* Arena::allocate(size_t size, size_t alignment) {
    if (size == 0) {
        return nullptr;
    }

    // Align current pointer
    uintptr_t current_addr = reinterpret_cast<uintptr_t>(current_);
    uintptr_t aligned_addr = align_up(current_addr, alignment);
    size_t padding = aligned_addr - current_addr;

    // Check if we have enough space
    size_t required = padding + size;
    size_t available = capacity_ - (current_ - buffer_);

    if (required > available) {
        // Try to grow the arena
        grow(required);

        // Recalculate after grow
        current_addr = reinterpret_cast<uintptr_t>(current_);
        aligned_addr = align_up(current_addr, alignment);
        padding = aligned_addr - current_addr;
        required = padding + size;
        available = capacity_ - (current_ - buffer_);

        if (required > available) {
            throw std::bad_alloc();
        }
    }

    // Allocate by bumping pointer
    void* result = reinterpret_cast<void*>(aligned_addr);
    current_ = reinterpret_cast<char*>(aligned_addr + size);

    return result;
}

void Arena::reset() {
    current_ = buffer_;
}

bool Arena::can_allocate(size_t size, size_t alignment) const {
    const uintptr_t current_addr = reinterpret_cast<uintptr_t>(current_);
    const uintptr_t aligned_addr = align_up(current_addr, alignment);
    const size_t padding = aligned_addr - current_addr;
    const size_t required = padding + size;
    const size_t available = capacity_ - (current_ - buffer_);

    return required <= available || (capacity_ * 2 <= max_capacity_);
}

uintptr_t Arena::align_up(uintptr_t ptr, size_t alignment) {
    // Ensure alignment is a power of 2
    if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
        alignment = alignof(std::max_align_t);
    }

    const uintptr_t mask = alignment - 1;
    return (ptr + mask) & ~mask;
}

void Arena::grow(size_t required_size) {
    // Calculate new capacity (double until we have enough)
    size_t new_capacity = capacity_;
    while (new_capacity - (current_ - buffer_) < required_size) {
        new_capacity *= 2;
        if (new_capacity > max_capacity_) {
            throw std::bad_alloc();
        }
    }

    // Allocate new buffer
    char* new_buffer = static_cast<char*>(
        std::aligned_alloc(alignof(std::max_align_t), new_capacity)
    );
    if (!new_buffer) {
        throw std::bad_alloc();
    }

    // Copy existing data
    const size_t used_size = current_ - buffer_;
    std::memcpy(new_buffer, buffer_, used_size);

    // Update pointers
    std::free(buffer_);
    buffer_ = new_buffer;
    current_ = buffer_ + used_size;
    capacity_ = new_capacity;
}

} // namespace sqlproxy
