#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>

namespace sqlproxy {

/**
 * @brief Per-request memory arena allocator
 *
 * Provides fast bump-pointer allocation for short-lived request objects.
 * All memory is freed in O(1) by resetting the pointer at request end.
 *
 * Performance characteristics:
 * - Allocation:  ~2ns (vs malloc ~50ns)
 * - Deallocation: O(1) for entire arena
 * - Zero fragmentation
 * - Cache-friendly (contiguous memory)
 *
 * Typical usage:
 *   Arena arena(1024);  // 1KB initial size
 *   auto* obj = arena.allocate<MyObject>(args...);
 *   // ... use obj ...
 *   arena.reset();  // Free all at once
 */
class Arena {
public:
    /**
     * @brief Construct arena with initial capacity
     * @param initial_size Initial size in bytes (default 1KB)
     * @param max_size Maximum size before throwing (default 64KB)
     */
    explicit Arena(size_t initial_size = 1024, size_t max_size = 65536);

    ~Arena();

    // Non-copyable, movable
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&& other) noexcept;
    Arena& operator=(Arena&& other) noexcept;

    /**
     * @brief Allocate raw memory with alignment
     * @param size Number of bytes to allocate
     * @param alignment Alignment requirement (default: alignof(max_align_t))
     * @return Pointer to allocated memory
     * @throws std::bad_alloc if arena is full and cannot grow
     */
    void* allocate(size_t size, size_t alignment = alignof(std::max_align_t));

    /**
     * @brief Allocate and construct object
     * @tparam T Object type
     * @tparam Args Constructor argument types
     * @param args Constructor arguments
     * @return Pointer to constructed object
     */
    template<typename T, typename... Args>
    T* allocate(Args&&... args) {
        void* mem = allocate(sizeof(T), alignof(T));
        return new (mem) T(std::forward<Args>(args)...);
    }

    /**
     * @brief Allocate array of objects
     * @tparam T Element type
     * @param count Number of elements
     * @return Pointer to first element
     */
    template<typename T>
    T* allocate_array(size_t count) {
        void* mem = allocate(sizeof(T) * count, alignof(T));
        // Placement new for each element (for non-trivial types)
        if constexpr (!std::is_trivially_constructible_v<T>) {
            T* arr = static_cast<T*>(mem);
            for (size_t i = 0; i < count; ++i) {
                new (&arr[i]) T();
            }
        }
        return static_cast<T*>(mem);
    }

    /**
     * @brief Reset arena, invalidating all allocations
     * @note Does NOT call destructors. Use for POD types or manually destroy objects.
     */
    void reset();

    /**
     * @brief Get current memory usage
     */
    size_t used() const { return current_ - buffer_; }

    /**
     * @brief Get total capacity
     */
    size_t capacity() const { return capacity_; }

    /**
     * @brief Get remaining space
     */
    size_t remaining() const { return capacity_ - used(); }

    /**
     * @brief Check if arena has enough space for allocation
     */
    bool can_allocate(size_t size, size_t alignment = alignof(std::max_align_t)) const;

private:
    /**
     * @brief Align pointer up to alignment
     */
    static uintptr_t align_up(uintptr_t ptr, size_t alignment);

    /**
     * @brief Grow arena to accommodate size
     */
    void grow(size_t required_size);

    char* buffer_;          // Start of memory block
    char* current_;         // Current allocation pointer
    size_t capacity_;       // Total capacity
    size_t max_capacity_;   // Maximum allowed capacity
    size_t initial_size_;   // Initial size for reset
};

// ============================================================================
// RAII Arena Scope Helper
// ============================================================================

/**
 * @brief RAII helper to automatically reset arena on scope exit
 *
 * Usage:
 *   Arena arena;
 *   {
 *       ArenaScope scope(arena);
 *       auto* obj = arena.allocate<MyObject>();
 *       // ... use obj ...
 *   }  // arena.reset() called automatically
 */
class ArenaScope {
public:
    explicit ArenaScope(Arena& arena) : arena_(arena) {}
    ~ArenaScope() { arena_.reset(); }

    ArenaScope(const ArenaScope&) = delete;
    ArenaScope& operator=(const ArenaScope&) = delete;

private:
    Arena& arena_;
};

} // namespace sqlproxy
